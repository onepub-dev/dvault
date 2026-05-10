use lockbox_core::{
    CacheLimit, Error, ExtractPolicy, ExtractedNode, KeySlotKind, ListOptions, Lockbox,
    LockboxOptions, MlKemKeyPair, RecoveryReportOptions,
};
use std::io::Cursor;

const KEY: &[u8] = b"public api suite key";
const PAGE_BYTES: usize = 8 * 1024 * 1024;
const PAGE_MAGIC: &[u8; 8] = b"LBX2PAG\0";
const KEY_DIR_MAGIC: &[u8; 8] = b"LBX2KEY\0";
const KEY_DIR_HEADER_LEN: usize = 128;

#[test]
fn public_api_files_listing_env_symlink_and_rename_flow() {
    let mut lb = Lockbox::create_with_options(
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(64 * 1024 * 1024),
        },
    );

    lb.put_file_with_permissions("/app/config.json", br#"{"mode":"test"}"#, 0o640)
        .unwrap();
    lb.put_file_from_reader("/app/logs/today.txt", Cursor::new(b"hello from a reader"))
        .unwrap();
    lb.put_symlink("/app/latest.log", "/app/logs/today.txt")
        .unwrap();
    lb.set_env("DATABASE_URL", "postgres://localhost/app")
        .unwrap();
    lb.set_env("API_TOKEN", "secret-token").unwrap();
    lb.rename("/app", "/srv/app").unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened.get_file("/srv/app/config.json").unwrap(),
        br#"{"mode":"test"}"#
    );
    assert_eq!(
        reopened
            .read_file_range("/srv/app/logs/today.txt", 6, 4)
            .unwrap(),
        b"from"
    );
    assert_eq!(reopened.permissions("/srv/app/config.json"), Some(0o640));
    assert!(reopened.is_symlink("/srv/app/latest.log"));
    assert_eq!(
        reopened.get_symlink_target("/srv/app/latest.log").unwrap(),
        "/app/logs/today.txt"
    );

    let entries = reopened
        .list_iter(ListOptions {
            path: "/srv".to_string(),
            glob: Some("**/*.txt".to_string()),
            recursive: true,
            include_files: true,
            include_symlinks: false,
            limit: None,
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "/srv/app/logs/today.txt");

    let env = reopened.get_all_env();
    assert_eq!(
        env.get("DATABASE_URL").map(String::as_str),
        Some("postgres://localhost/app")
    );
    assert_eq!(
        reopened.get_env("API_TOKEN").unwrap().as_deref(),
        Some("secret-token")
    );
    assert!(reopened.list("/srv").unwrap().iter().all(|entry| {
        !entry.path.contains("DATABASE_URL") && !entry.path.contains("API_TOKEN")
    }));

    let nodes = reopened
        .extract_all_nodes(&ExtractPolicy {
            restore_symlinks: true,
            ..ExtractPolicy::default()
        })
        .unwrap();
    assert!(nodes.iter().any(|node| matches!(
        node,
        ExtractedNode::File(file)
            if file.path == "/srv/app/config.json" && file.permissions == 0o640
    )));
    assert!(nodes.iter().any(|node| matches!(
        node,
        ExtractedNode::Symlink(link)
            if link.path == "/srv/app/latest.log" && link.target == "/app/logs/today.txt"
    )));
}

#[test]
fn public_api_password_and_recipient_key_management_flow() {
    let recipient = MlKemKeyPair::generate();
    let mut lb = Lockbox::create_with_password(b"old-password").unwrap();
    let password_slot = lb.list_key_slots()[0].id;
    let recipient_slot = lb.add_recipient(&recipient).unwrap();

    lb.put_file("/secret.txt", b"shared").unwrap();
    lb.commit().unwrap();

    let bytes = lb.to_bytes();
    assert_eq!(
        Lockbox::open_with_password(bytes.clone(), b"old-password")
            .unwrap()
            .get_file("/secret.txt")
            .unwrap(),
        b"shared"
    );
    assert_eq!(
        Lockbox::open_with_recipient(bytes.clone(), &recipient)
            .unwrap()
            .get_file("/secret.txt")
            .unwrap(),
        b"shared"
    );

    let mut reopened = Lockbox::open_with_password(bytes, b"old-password").unwrap();
    let new_slot = reopened
        .change_password(b"old-password", b"new-password")
        .unwrap();
    reopened
        .remove_key_slot_and_compact(recipient_slot)
        .unwrap();
    reopened.commit().unwrap();

    let slots = reopened.list_key_slots();
    assert!(slots
        .iter()
        .any(|slot| slot.id == new_slot && slot.kind == KeySlotKind::Password));
    assert!(slots.iter().all(|slot| slot.id != password_slot));
    assert!(slots.iter().all(|slot| slot.id != recipient_slot));
    assert!(Lockbox::open_with_password(reopened.to_bytes(), b"new-password").is_ok());
}

#[test]
fn page_checksum_corruption_is_reported_and_recovery_keeps_intact_files() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file_from_reader("/large/a.bin", Cursor::new(vec![b'a'; 2 * 1024 * 1024]))
        .unwrap();
    lb.commit().unwrap();
    lb.put_file_from_reader("/large/b.bin", Cursor::new(vec![b'b'; 2 * 1024 * 1024]))
        .unwrap();
    lb.commit().unwrap();

    let damaged = damage_page_that_makes_a_file_partial(lb.to_bytes());

    let report = Lockbox::recover(damaged.clone(), KEY);
    assert!(report.corrupt_records > 0);
    assert!(report.partial_files > 0);
    assert!(report.intact_file_count > 0);
    assert!(report
        .render(&RecoveryReportOptions::default())
        .contains("Corrupt records"));

    let salvaged = Lockbox::salvage(damaged, KEY).unwrap();
    let a = salvaged.get_file("/large/a.bin");
    let b = salvaged.get_file("/large/b.bin");
    assert!(
        a.is_ok() || b.is_ok(),
        "at least one file should survive salvage"
    );
    assert!(
        matches!(a, Err(Error::NotFound(_))) || matches!(b, Err(Error::NotFound(_))),
        "the file on the corrupt page should be omitted"
    );
}

#[test]
fn key_directory_payload_checksum_falls_back_to_mirror_copy() {
    let mut lb = Lockbox::create_with_password(b"password").unwrap();
    lb.put_file("/secret.txt", b"content").unwrap();
    lb.commit().unwrap();

    let mut damaged = lb.to_bytes();
    let primary_offset = u64::from_le_bytes(damaged[32..40].try_into().unwrap()) as usize;
    assert_eq!(&damaged[primary_offset..primary_offset + 8], KEY_DIR_MAGIC);
    damaged[primary_offset + KEY_DIR_HEADER_LEN] ^= 0x01;

    let reopened = Lockbox::open_with_password(damaged, b"password").unwrap();
    assert_eq!(reopened.get_file("/secret.txt").unwrap(), b"content");
}

fn find_page_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut index = 0usize;
    while index + PAGE_MAGIC.len() <= bytes.len() {
        if &bytes[index..index + PAGE_MAGIC.len()] == PAGE_MAGIC {
            offsets.push(index);
            index = index.saturating_add(PAGE_BYTES);
        } else {
            index += 1;
        }
    }
    offsets
}

fn damage_page_that_makes_a_file_partial(bytes: Vec<u8>) -> Vec<u8> {
    for offset in find_page_offsets(&bytes) {
        let mut candidate = bytes.clone();
        candidate[offset + 16] ^= 0x01;
        let report = Lockbox::recover(candidate.clone(), KEY);
        if report.corrupt_records > 0 && report.partial_files > 0 && report.intact_file_count > 0 {
            return candidate;
        }
    }
    panic!("test fixture did not produce an independently recoverable corrupt page");
}
