use lockbox_core::{
    CacheLimit, Error, ExtractPolicy, ExtractedNode, KeySlotKind, ListOptions, Lockbox,
    LockboxCreate, LockboxId, LockboxOptions, LockboxUnlock, MlKemKeyPair, MlKemRecipientKey,
    MlKemWrappedKey, RecoveryReportOptions, SecretString, SecretVec, WorkloadProfile,
};
use std::io::Cursor;
use std::path::PathBuf;

const KEY: &[u8] = b"public api suite key";
const PAGE_BYTES: usize = 8 * 1024 * 1024;
const PAGE_MAGIC: &[u8; 8] = b"LBX2PAG\0";
const PAGE_HEADER_LEN: usize = 96;

#[test]
fn public_api_files_listing_env_symlink_and_rename_flow() {
    let mut lb = Lockbox::create_with_options(
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(64 * 1024 * 1024),
            ..LockboxOptions::default()
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

    let env = reopened.get_all_env().unwrap();
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
    let recipient = MlKemKeyPair::generate().unwrap();
    let old_password = password("old-password");
    let new_password = password("new-password");
    let mut lb = Lockbox::create_with_password(&old_password).unwrap();
    let password_slot = lb.list_key_slots()[0].id;
    let recipient_slot = lb.add_recipient(&recipient).unwrap();

    lb.put_file("/secret.txt", b"shared").unwrap();
    lb.commit().unwrap();

    let bytes = lb.to_bytes();
    assert_eq!(
        Lockbox::open_with_password(bytes.clone(), &old_password)
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

    let mut reopened = Lockbox::open_with_password(bytes, &old_password).unwrap();
    let new_slot = reopened
        .change_password(&old_password, &new_password)
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
    assert!(Lockbox::open_with_password(reopened.to_bytes(), &new_password).is_ok());
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
fn key_directory_page_checksum_falls_back_to_mirror_copy() {
    let password = password("password");
    let mut lb = Lockbox::create_with_password(&password).unwrap();
    lb.put_file("/secret.txt", b"content").unwrap();
    lb.commit().unwrap();

    let mut damaged = lb.to_bytes();
    let primary_offset = u64::from_le_bytes(damaged[32..40].try_into().unwrap()) as usize;
    assert_eq!(&damaged[primary_offset..primary_offset + 8], PAGE_MAGIC);
    damaged[primary_offset + PAGE_HEADER_LEN + 40] ^= 0x01;

    let reopened = Lockbox::open_with_password(damaged, &password).unwrap();
    assert_eq!(reopened.get_file("/secret.txt").unwrap(), b"content");
}

#[test]
fn key_directory_pages_only_change_for_key_crud() {
    let password = password("password");
    let mut lb = Lockbox::create_with_password(&password).unwrap();
    lb.commit().unwrap();
    let mut bytes = lb.to_bytes();
    let first_key_dir_offset = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;

    lb.put_file("/secret.txt", b"content").unwrap();
    lb.commit().unwrap();
    bytes = lb.to_bytes();
    assert_eq!(
        u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize,
        first_key_dir_offset
    );

    let recipient = MlKemKeyPair::generate().unwrap();
    lb.add_recipient(&recipient).unwrap();
    lb.commit().unwrap();
    bytes = lb.to_bytes();
    let second_key_dir_offset = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    assert_ne!(second_key_dir_offset, first_key_dir_offset);
    assert!(
        bytes[first_key_dir_offset..first_key_dir_offset + 128 * 1024]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn public_api_secret_lockbox_id_and_ml_kem_wrappers_flow() {
    let mut secret = SecretString::new();
    assert!(secret.is_empty());
    secret.try_push_byte(b'a').unwrap();
    secret.try_push_byte(b'b').unwrap();
    secret.try_push_utf8_char('c').unwrap();
    assert_eq!(secret.with_str(|text| text.to_owned()).unwrap(), "abc");
    secret
        .with_bytes(|bytes| assert_eq!(bytes, b"abc"))
        .unwrap();
    assert_eq!(secret.try_pop_byte().unwrap(), Some(b'c'));
    secret.zeroize().unwrap();
    assert!(secret.is_empty());
    assert!(format!("{secret:?}").contains("redacted"));

    let secret_vec = SecretVec::try_from_vec(vec![1, 2, 3]).unwrap();
    secret_vec
        .with_bytes(|bytes| assert_eq!(bytes, &[1, 2, 3]))
        .unwrap();
    assert!(format!("{secret_vec:?}").contains("redacted"));

    let lockbox_id = LockboxId::from_bytes([
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x4d, 0xef, 0x80, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
        0xde,
    ]);
    assert_eq!(lockbox_id.as_bytes()[0], 0x12);
    assert_eq!(
        lockbox_id.to_string(),
        "12345678-9abc-4def-8012-3456789abcde"
    );
    let random_id = LockboxId::new_random().unwrap();
    assert_eq!(random_id.as_bytes()[6] & 0xf0, 0x40);
    assert_eq!(random_id.as_bytes()[8] & 0xc0, 0x80);

    let keypair = MlKemKeyPair::generate().unwrap();
    let from_seed = MlKemKeyPair::from_seed_secure(keypair.to_seed_secure().unwrap()).unwrap();
    let recipient = keypair.recipient_key();
    let recipient = MlKemRecipientKey::from_bytes(&recipient.to_bytes()).unwrap();
    let wrapped = recipient.wrap_key(b"content-key").unwrap();
    let wrapped = MlKemWrappedKey::from_parts(
        wrapped.ciphertext_bytes().to_vec(),
        wrapped.encrypted_key().to_vec(),
    )
    .unwrap();
    assert_eq!(from_seed.unwrap_key(&wrapped).unwrap(), b"content-key");
    assert_eq!(
        from_seed
            .wrap_key(b"another-key")
            .unwrap()
            .encrypted_key()
            .len(),
        27
    );
}

#[test]
fn public_api_path_cache_recovery_and_file_helpers_flow() {
    let root = unique_dir("core-public-api");
    let lockbox_path = root.join("raw.lbox");
    let source_path = root.join("source.txt");
    let extract_path = root.join("extracted.txt");
    let written_path = root.join("written.lbox");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&source_path, b"from disk").unwrap();

    let lockbox_id = LockboxId::from_bytes(*b"public-api-id-01");
    let mut lb = Lockbox::create_with_lockbox_id_and_options(
        KEY,
        lockbox_id,
        LockboxOptions {
            cache_limit: CacheLimit::Disabled,
            workload_profile: WorkloadProfile::BulkImport,
        },
    );
    assert_eq!(lb.lockbox_id(), lockbox_id);
    assert_eq!(lb.workload_profile(), WorkloadProfile::BulkImport);
    lb.set_workload_profile(WorkloadProfile::ReadMostly);
    assert_eq!(lb.workload_profile(), WorkloadProfile::ReadMostly);

    lb.add_file(&source_path, "/docs/source.txt").unwrap();
    lb.add_file_from_reader("/docs/reader.txt", Cursor::new(b"from reader"))
        .unwrap();
    lb.set_env("TEMP", "1").unwrap();
    lb.delete_env_var("TEMP").unwrap();
    lb.commit().unwrap();

    let entries = lb.list_iter(ListOptions::new("/docs")).unwrap();
    assert_eq!(entries.count(), 2);
    let mut out = Vec::new();
    lb.write_file_to("/docs/source.txt", &mut out).unwrap();
    assert_eq!(out, b"from disk");
    out.clear();
    lb.extract_file_to_writer("/docs/reader.txt", &mut out)
        .unwrap();
    assert_eq!(out, b"from reader");
    lb.extract_file_to("/docs/source.txt", &extract_path)
        .unwrap();
    assert_eq!(std::fs::read(&extract_path).unwrap(), b"from disk");

    let bytes = lb.to_bytes();
    assert_eq!(Lockbox::read_lockbox_id(&bytes).unwrap(), lockbox_id);
    assert!(lb.storage_len().unwrap() > 0);
    assert!(!lb.inspect_pages().unwrap().is_empty());
    lb.set_cache_limit(CacheLimit::Bytes(1024));
    lb.trim_cache_to(0);
    lb.trim_cache();
    assert_eq!(lb.cache_stats().used_bytes, 0);
    assert_eq!(lb.recover_current().intact_file_count, 2);

    lb.write_to_path(&written_path).unwrap();
    assert_eq!(
        Lockbox::read_lockbox_id_path(&written_path).unwrap(),
        lockbox_id
    );
    let reopened = Lockbox::open_path_with_options(
        &written_path,
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(1024 * 1024),
            workload_profile: WorkloadProfile::ExtractMany,
        },
    )
    .unwrap();
    assert_eq!(reopened.workload_profile(), WorkloadProfile::ExtractMany);
    assert_eq!(reopened.get_file("/docs/source.txt").unwrap(), b"from disk");
    assert_eq!(
        Lockbox::recover_path(&written_path, KEY).intact_file_count,
        2
    );

    let mut file_backed = Lockbox::create_path_with_options(
        &lockbox_path,
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Disabled,
            workload_profile: WorkloadProfile::Interactive,
        },
    )
    .unwrap();
    file_backed.put_file("/a.txt", b"alpha").unwrap();
    file_backed.commit().unwrap();
    assert_eq!(
        Lockbox::open_path(&lockbox_path, KEY)
            .unwrap()
            .get_file("/a.txt")
            .unwrap(),
        b"alpha"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn public_api_password_recipient_unlock_helper_flow() {
    let root = unique_dir("core-key-api");
    let password_path = root.join("password.lbox");
    let recipient_path = root.join("recipient.lbox");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let password = password("shared-password");
    let mut by_password =
        Lockbox::create_file(&password_path, LockboxCreate::Password(&password)).unwrap();
    by_password.put_file("/secret.txt", b"password").unwrap();
    by_password.commit().unwrap();
    let unlocked = Lockbox::unlock_path_with_password(&password_path, &password).unwrap();
    assert_eq!(unlocked.lockbox_id, by_password.lockbox_id());
    unlocked.with_key(|key| assert_eq!(key.len(), 32)).unwrap();
    assert_eq!(
        Lockbox::open_file(&password_path, LockboxUnlock::Password(&password))
            .unwrap()
            .get_file("/secret.txt")
            .unwrap(),
        b"password"
    );
    let password_backup = by_password.export_key_directory_backup().unwrap();
    assert_eq!(
        Lockbox::unlock_key_directory_backup_with_password(&password_backup, &password)
            .unwrap()
            .lockbox_id,
        by_password.lockbox_id()
    );

    let recipient = MlKemKeyPair::generate().unwrap();
    let mut by_recipient = Lockbox::create_file(
        &recipient_path,
        LockboxCreate::RecipientKey(recipient.recipient_key()),
    )
    .unwrap();
    by_recipient.put_file("/secret.txt", b"recipient").unwrap();
    by_recipient.commit().unwrap();
    assert_eq!(
        Lockbox::open_file(&recipient_path, LockboxUnlock::RecipientKey(recipient))
            .unwrap()
            .get_file("/secret.txt")
            .unwrap(),
        b"recipient"
    );

    let recipient = MlKemKeyPair::generate().unwrap();
    let recipient_backup = {
        let mut lb = Lockbox::create_with_recipient(&recipient).unwrap();
        lb.put_file("/a.txt", b"a").unwrap();
        lb.commit().unwrap();
        assert_eq!(
            Lockbox::open_with_recipient(lb.to_bytes(), &recipient)
                .unwrap()
                .get_file("/a.txt")
                .unwrap(),
            b"a"
        );
        lb.export_key_directory_backup().unwrap()
    };
    assert_eq!(
        Lockbox::unlock_key_directory_backup_with_recipient(&recipient_backup, &recipient)
            .unwrap()
            .with_key(|key| assert_eq!(key.len(), 32)),
        Ok(())
    );

    let mut lb = Lockbox::create_with_recipient_key(&recipient.recipient_key()).unwrap();
    let password_slot = lb.add_password_slot(&password).unwrap();
    lb.delete_key_slot(password_slot).unwrap();
    let extra_recipient = MlKemKeyPair::generate().unwrap();
    let extra_slot = lb.add_recipient(&extra_recipient).unwrap();
    lb.delete_key_slot_and_compact(extra_slot).unwrap();
    assert_eq!(lb.list_key_slots().len(), 1);

    let _ = std::fs::remove_dir_all(root);
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

fn password(value: &str) -> SecretString {
    SecretString::try_from_bytes(value.as_bytes().to_vec()).unwrap()
}

fn unique_dir(label: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/test-tmp")
        .join(format!(
            "lockbox-core-public-api-{label}-{}-{}",
            std::process::id(),
            monotonic_suffix()
        ))
}

fn monotonic_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
