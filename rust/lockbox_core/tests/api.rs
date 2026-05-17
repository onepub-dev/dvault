use lockbox_core::{
    CacheLimit, Entry, EntryKind, Error, ExtractPolicy, ExtractedNode, KeySlotKind, ListOptions,
    Lockbox, LockboxCreate, LockboxOptions, LockboxUnlock, MlKemKeyPair, MlKemRecipientKey,
    RecoveryReportOptions, SecretString, WorkloadProfile,
};
use sha2::{Digest, Sha256};
use std::io::Cursor;

const KEY: &[u8] = b"correct horse battery staple";
const HEADER_LEN: usize = 96;
const HEADER_CHECKSUM_START: usize = 64;
const METADATA_PAGE_BYTES: usize = 128 * 1024;
const PAGE_BYTES: usize = 8 * 1024 * 1024;

#[test]
fn create_put_get_list_stat_commit_open() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_file("/docs/b.txt", b"bravo").unwrap();

    assert_eq!(lb.get_file("/docs/a.txt").unwrap(), b"alpha");
    assert_eq!(lb.read_file_range("/docs/b.txt", 1, 3).unwrap(), b"rav");
    assert_eq!(
        lb.stat("/docs/a.txt"),
        Some(Entry {
            path: "/docs/a.txt".to_string(),
            kind: EntryKind::File,
            len: 5,
            permissions: 0o600,
            symlink_target: None,
            is_deleted: false,
        })
    );

    let listed = lb.list("/docs").unwrap();
    assert_eq!(listed.len(), 2);

    lb.commit().unwrap();
    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file("/docs/a.txt").unwrap(), b"alpha");
    assert_eq!(reopened.get_file("/docs/b.txt").unwrap(), b"bravo");
}

#[test]
fn write_to_path_and_open_path_round_trip() {
    let path = std::env::temp_dir().join(format!("lockbox-path-{}.lbx", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.commit().unwrap();
    lb.write_to_path(&path).unwrap();

    let reopened = Lockbox::open_path(&path, KEY).unwrap();
    assert_eq!(reopened.get_file("/docs/a.txt").unwrap(), b"alpha");
    assert_eq!(reopened.to_bytes(), std::fs::read(&path).unwrap());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_path_writes_file_backed_lockbox() {
    let path = std::env::temp_dir().join(format!("lockbox-create-path-{}.lbx", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let mut lb = Lockbox::create_path(&path, KEY).unwrap();
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.commit().unwrap();

    let bytes_on_disk = std::fs::read(&path).unwrap();
    assert_eq!(
        Lockbox::open(bytes_on_disk.clone(), KEY)
            .unwrap()
            .get_file("/docs/a.txt")
            .unwrap(),
        b"alpha"
    );
    assert_eq!(
        Lockbox::open_path(&path, KEY).unwrap().to_bytes(),
        bytes_on_disk
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn small_files_are_staged_until_commit_then_packed() {
    let mut lb = Lockbox::create(KEY);
    let before = lb.to_bytes().len();

    lb.put_file("/tiny.txt", b"x").unwrap();

    assert_eq!(lb.to_bytes().len(), before);
    assert_eq!(lb.get_file("/tiny.txt").unwrap(), b"x");

    lb.commit().unwrap();
    let after = lb.to_bytes().len();

    assert!(after - before <= 4 * PAGE_BYTES);
    assert_eq!(lb.get_file("/tiny.txt").unwrap(), b"x");
}

#[test]
fn add_file_stages_small_disk_files_until_commit() {
    let source = std::env::temp_dir().join(format!(
        "lockbox-small-source-{}-{}.txt",
        std::process::id(),
        "add-file"
    ));
    std::fs::write(&source, b"tiny source file").unwrap();

    let mut lb = Lockbox::create(KEY);
    let before = lb.to_bytes().len();
    lb.add_file(&source, "/from-disk.txt").unwrap();

    assert_eq!(lb.to_bytes().len(), before);
    assert_eq!(lb.get_file("/from-disk.txt").unwrap(), b"tiny source file");

    lb.commit().unwrap();
    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened.get_file("/from-disk.txt").unwrap(),
        b"tiny source file"
    );

    let _ = std::fs::remove_file(&source);
}

#[test]
fn small_env_pages_are_padded_to_minimum_size() {
    let mut lb = Lockbox::create(KEY);
    let before = lb.to_bytes().len();

    lb.set_env("TOKEN", "x").unwrap();

    lb.commit().unwrap();
    assert!(lb.inspect_pages().unwrap().iter().any(|page| {
        page.objects
            .iter()
            .any(|object| object.kind == "env-leaf" && object.payload_len > 0)
    }));
    let after = lb.to_bytes().len();

    assert!(after >= before + 2 * METADATA_PAGE_BYTES);
    assert_eq!(lb.get_env("TOKEN").unwrap().as_deref(), Some("x"));
}

#[test]
fn env_scan_fails_closed_when_env_page_is_corrupt() {
    let mut lb = Lockbox::create(KEY);
    lb.set_env("TOKEN", "x").unwrap();
    lb.commit().unwrap();

    let env_page = lb
        .inspect_pages()
        .unwrap()
        .into_iter()
        .find(|page| page.objects.iter().any(|object| object.kind == "env-leaf"))
        .unwrap();
    let mut bytes = lb.to_bytes();
    bytes[env_page.offset as usize + HEADER_LEN + 8] ^= 0x55;

    let reopened = Lockbox::open(bytes, KEY).unwrap();
    assert!(reopened.get_env("TOKEN").is_err());
}

#[test]
fn invalid_paths_are_rejected() {
    let mut lb = Lockbox::create(KEY);

    for path in [
        "",
        "relative.txt",
        "/",
        "/dir/",
        "/../escape.txt",
        "/safe/../escape.txt",
        "/safe/./file.txt",
        "/safe//file.txt",
        "/C:/windows.txt",
        "/safe/name:ads",
        "//server/share/file.txt",
        "/safe\\windows\\path.txt",
        "/safe/\0nul.txt",
        "/safe/\nnewline.txt",
    ] {
        assert!(
            matches!(lb.put_file(path, b"x"), Err(Error::InvalidPath(_))),
            "path should be rejected: {path:?}"
        );
    }

    assert!(matches!(lb.list("relative"), Err(Error::InvalidPath(_))));
    assert!(matches!(lb.list("/safe/.."), Err(Error::InvalidPath(_))));
}

#[test]
fn path_depth_and_length_limits_are_enforced() {
    let mut lb = Lockbox::create(KEY);
    let too_deep = format!("/{}", vec!["x"; 65].join("/"));
    let too_long = format!("/{}", "a".repeat(4097));

    assert!(matches!(
        lb.put_file(&too_deep, b"x"),
        Err(Error::InvalidPath(_))
    ));
    assert!(matches!(
        lb.put_file(&too_long, b"x"),
        Err(Error::InvalidPath(_))
    ));
}

#[test]
fn unicode_paths_round_trip() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/résumé.pdf", b"cv").unwrap();
    lb.put_file("/写真/旅行.jpg", b"photo").unwrap();
    lb.put_file("/客户/合同.txt", b"contract").unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file("/docs/résumé.pdf").unwrap(), b"cv");
    assert_eq!(reopened.get_file("/写真/旅行.jpg").unwrap(), b"photo");
    assert_eq!(reopened.get_file("/客户/合同.txt").unwrap(), b"contract");
}

#[test]
fn unicode_paths_are_canonicalized_to_nfc_for_storage_and_lookup() {
    let mut lb = Lockbox::create(KEY);
    let decomposed = "/docs/re\u{0301}sume\u{0301}.pdf";
    let composed = "/docs/résumé.pdf";

    lb.put_file(decomposed, b"cv").unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file(composed).unwrap(), b"cv");
    assert_eq!(reopened.get_file(decomposed).unwrap(), b"cv");
    assert!(reopened.stat(composed).is_some());
    assert_eq!(reopened.list("/docs").unwrap()[0].path, composed);
}

#[test]
fn unicode_normalization_collisions_replace_same_logical_path() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/re\u{0301}sume\u{0301}.pdf", b"one")
        .unwrap();
    lb.put_file("/docs/résumé.pdf", b"two").unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file("/docs/résumé.pdf").unwrap(), b"two");
    assert_eq!(reopened.list("/docs").unwrap().len(), 1);
}

#[test]
fn unicode_bidi_and_invisible_controls_are_rejected() {
    let mut lb = Lockbox::create(KEY);
    for path in [
        "/docs/report\u{202e}fdp.txt",
        "/docs/report\u{2066}.txt",
        "/docs/zero\u{200b}width.txt",
        "/docs/joiner\u{200d}.txt",
        "/docs/variation\u{fe0f}.txt",
        "/docs/c1\u{0085}.txt",
    ] {
        assert!(
            matches!(lb.put_file(path, b"x"), Err(Error::InvalidPath(_))),
            "path should be rejected: {path:?}"
        );
    }
}

#[test]
fn empty_and_large_files_round_trip() {
    let large: Vec<u8> = (0..128_000).map(|i| (i % 251) as u8).collect();
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/empty.bin", b"").unwrap();
    lb.put_file("/large.bin", &large).unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file("/empty.bin").unwrap(), b"");
    assert_eq!(reopened.get_file("/large.bin").unwrap(), large);
    assert_eq!(
        reopened.read_file_range("/large.bin", 12_345, 100).unwrap(),
        large[12_345..12_445]
    );
}

#[test]
fn file_content_can_be_loaded_and_extracted_with_streaming_apis() {
    let mut lb = Lockbox::create(KEY);
    let content = vec![42u8; 8 * 1024 * 1024 + 123];

    lb.put_file_from_reader("/large/stream.bin", Cursor::new(&content))
        .unwrap();

    let mut extracted = Vec::new();
    lb.write_file_to("/large/stream.bin", &mut extracted)
        .unwrap();
    assert_eq!(extracted, content);
}

#[test]
fn content_keys_can_be_wrapped_with_ml_kem_1024() {
    let key_pair = MlKemKeyPair::generate().unwrap();
    let content_key = [9u8; 32];

    let wrapped = key_pair.wrap_key(&content_key).unwrap();
    let unwrapped = key_pair.unwrap_key(&wrapped).unwrap();

    assert_eq!(unwrapped, content_key);
    assert!(!wrapped.encrypted_key().is_empty());
}

#[test]
fn password_slots_unlock_the_random_content_key() {
    let share_password = password("share-password");
    let mut lb = Lockbox::create_with_password(&share_password).unwrap();
    let lockbox_id = lb.lockbox_id();
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.commit().unwrap();

    let bytes = lb.to_bytes();
    assert_eq!(Lockbox::read_lockbox_id(&bytes).unwrap(), lockbox_id);
    assert!(matches!(
        Lockbox::open_with_password(bytes.clone(), &password("wrong-password")),
        Err(Error::InvalidKey)
    ));

    let reopened = Lockbox::open_with_password(bytes, &share_password).unwrap();
    assert_eq!(reopened.lockbox_id(), lockbox_id);
    assert_eq!(reopened.get_file("/docs/a.txt").unwrap(), b"alpha");
    assert_eq!(reopened.list_key_slots()[0].kind, KeySlotKind::Password);
}

#[test]
fn password_unlock_recovers_when_header_is_corrupt() {
    let share_password = password("share-password");
    let mut lb = Lockbox::create_with_password(&share_password).unwrap();
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.commit().unwrap();

    let mut bytes = lb.to_bytes();
    bytes[0] ^= 0xff;

    let reopened = Lockbox::open_with_password(bytes, &share_password).unwrap();
    assert_eq!(reopened.get_file("/docs/a.txt").unwrap(), b"alpha");
}

#[test]
fn password_unlock_recovers_when_primary_key_directory_is_corrupt() {
    let share_password = password("share-password");
    let mut lb = Lockbox::create_with_password(&share_password).unwrap();
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.commit().unwrap();

    let mut bytes = lb.to_bytes();
    let primary_key_directory_offset =
        u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    bytes[primary_key_directory_offset] ^= 0xff;

    let reopened = Lockbox::open_with_password(bytes, &share_password).unwrap();
    assert_eq!(reopened.get_file("/docs/a.txt").unwrap(), b"alpha");
}

#[test]
fn multiple_key_slots_are_tried_until_one_unlocks() {
    let alice = MlKemKeyPair::generate().unwrap();
    let bob = MlKemKeyPair::generate().unwrap();
    let outsider = MlKemKeyPair::generate().unwrap();
    let bob_public = MlKemRecipientKey::from_bytes(&bob.recipient_key().to_bytes()).unwrap();

    let mut lb = Lockbox::create_with_recipient_key(&alice.recipient_key()).unwrap();
    lb.add_recipient_key(&bob_public).unwrap();
    let backup_password = password("backup-password");
    lb.add_password_slot(&backup_password).unwrap();
    lb.put_file("/shared/report.txt", b"report").unwrap();
    lb.commit().unwrap();

    let bytes = lb.to_bytes();
    assert!(matches!(
        Lockbox::open_with_recipient(bytes.clone(), &outsider),
        Err(Error::InvalidKey)
    ));

    let by_bob = Lockbox::open_with_recipient(bytes.clone(), &bob).unwrap();
    assert_eq!(by_bob.get_file("/shared/report.txt").unwrap(), b"report");

    let by_password = Lockbox::open_with_password(bytes, &backup_password).unwrap();
    assert_eq!(
        by_password.get_file("/shared/report.txt").unwrap(),
        b"report"
    );
    assert_eq!(by_password.list_key_slots().len(), 3);
}

#[test]
fn key_slots_can_be_removed_and_passwords_changed() {
    let old_password = password("old-password");
    let temporary_password = password("temporary-password");
    let new_password = password("new-password");
    let mut lb = Lockbox::create_with_password(&old_password).unwrap();
    let extra_id = lb.add_password_slot(&temporary_password).unwrap();
    lb.remove_key_slot(extra_id).unwrap();
    lb.change_password(&old_password, &new_password).unwrap();
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.commit().unwrap();

    let bytes = lb.to_bytes();
    assert!(matches!(
        Lockbox::open_with_password(bytes.clone(), &old_password),
        Err(Error::InvalidKey)
    ));
    assert!(matches!(
        Lockbox::open_with_password(bytes.clone(), &temporary_password),
        Err(Error::InvalidKey)
    ));

    let reopened = Lockbox::open_with_password(bytes, &new_password).unwrap();
    assert_eq!(reopened.get_file("/docs/a.txt").unwrap(), b"alpha");
    assert_eq!(reopened.list_key_slots().len(), 1);
}

#[test]
fn key_slot_removal_compacts_old_key_material() {
    let primary_password = password("primary-password");
    let temporary_password = password("temporary-password");
    let mut lb = Lockbox::create_with_password(&primary_password).unwrap();
    let temporary_id = lb.add_password_slot(&temporary_password).unwrap();
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.commit().unwrap();
    let before = lb.to_bytes().len();

    lb.remove_key_slot_and_compact(temporary_id).unwrap();
    let bytes = lb.to_bytes();

    assert!(bytes.len() <= before);
    assert!(matches!(
        Lockbox::open_with_password(bytes.clone(), &temporary_password),
        Err(Error::InvalidKey)
    ));
    let reopened = Lockbox::open_with_password(bytes, &primary_password).unwrap();
    assert_eq!(reopened.get_file("/docs/a.txt").unwrap(), b"alpha");
    assert_eq!(reopened.list_key_slots().len(), 1);
}

#[test]
fn path_backed_key_slot_removal_compacts_and_remains_file_backed() {
    let path = temp_path("path-backed-key-compaction");
    let primary_password = password("primary-password");
    let temporary_password = password("temporary-password");
    let mut lb = Lockbox::create_file(&path, LockboxCreate::Password(&primary_password)).unwrap();
    let temporary_id = lb.add_password_slot(&temporary_password).unwrap();
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.commit().unwrap();
    let before = std::fs::metadata(&path).unwrap().len();

    lb.delete_key_slot_and_compact(temporary_id).unwrap();
    lb.put_file("/docs/b.txt", b"bravo").unwrap();
    lb.commit().unwrap();
    let after = std::fs::metadata(&path).unwrap().len();

    assert!(after <= before + 4 * PAGE_BYTES as u64);
    assert!(matches!(
        Lockbox::open_file(&path, LockboxUnlock::Password(&temporary_password)),
        Err(Error::InvalidKey)
    ));
    let reopened = Lockbox::open_file(&path, LockboxUnlock::Password(&primary_password)).unwrap();
    assert_eq!(reopened.get_file("/docs/a.txt").unwrap(), b"alpha");
    assert_eq!(reopened.get_file("/docs/b.txt").unwrap(), b"bravo");

    let _ = std::fs::remove_file(path);
}

#[test]
fn oversized_key_directories_are_rejected() {
    let share_password = password("share-password");
    let mut lb = Lockbox::create_with_password(&share_password).unwrap();
    lb.commit().unwrap();

    let mut bytes = lb.to_bytes();
    let mut offset = 64usize;
    while offset + 24 <= bytes.len() {
        if bytes.get(offset..offset + 8) == Some(b"LBX2KEY\0".as_slice()) {
            bytes[offset + 16..offset + 24].copy_from_slice(&(2 * 1024 * 1024u64).to_le_bytes());
            offset += 64;
        } else {
            offset += 1;
        }
    }

    assert!(matches!(
        Lockbox::open_with_password(bytes, &share_password),
        Err(Error::SecurityLimitExceeded(_) | Error::InvalidKey | Error::CorruptHeader)
    ));
}

#[test]
fn compressible_page_content_uses_less_space_than_raw_chunks() {
    let mut lb = Lockbox::create(KEY);
    let compressible = vec![b'a'; 2 * 1024 * 1024];

    lb.put_file("/compressible.bin", &compressible).unwrap();
    let vault_len = lb.to_bytes().len();

    assert!(vault_len < 4 * PAGE_BYTES);
    assert_eq!(lb.get_file("/compressible.bin").unwrap(), compressible);
}

#[test]
fn compressible_large_file_uses_fewer_pages_than_incompressible_large_file() {
    let compressible = vec![0u8; 16 * 1024 * 1024];
    let mut incompressible = vec![0u8; compressible.len()];
    fill_randomish(&mut incompressible);

    let mut compressible_box = Lockbox::create(KEY);
    compressible_box
        .put_file("/compressible.bin", &compressible)
        .unwrap();
    compressible_box.commit().unwrap();

    let mut incompressible_box = Lockbox::create(KEY);
    incompressible_box
        .put_file("/incompressible.bin", &incompressible)
        .unwrap();
    incompressible_box.commit().unwrap();

    let compressible_len = compressible_box.to_bytes().len();
    let incompressible_len = incompressible_box.to_bytes().len();
    assert!(
        compressible_len + PAGE_BYTES <= incompressible_len,
        "compressible vault should save at least one fixed page: {compressible_len} vs {incompressible_len}"
    );
    assert_eq!(
        compressible_box.get_file("/compressible.bin").unwrap(),
        compressible
    );
    assert_eq!(
        incompressible_box.get_file("/incompressible.bin").unwrap(),
        incompressible
    );
}

#[test]
fn many_small_files_are_packed_into_shared_pages_after_commit() {
    let mut lb = Lockbox::create(KEY);
    let initial_len = lb.to_bytes().len();
    for i in 0..20 {
        lb.put_file(&format!("/packed/file-{i}.txt"), b"tiny")
            .unwrap();
    }
    assert_eq!(lb.to_bytes().len(), initial_len);

    lb.commit().unwrap();

    let bytes = lb.to_bytes();
    let len_after_first_commit = bytes.len();
    assert!(len_after_first_commit <= initial_len + 4 * PAGE_BYTES);

    for i in 20..30 {
        lb.put_file(&format!("/packed/file-{i}.txt"), b"tiny")
            .unwrap();
    }
    lb.commit().unwrap();
    assert!(lb.to_bytes().len() <= len_after_first_commit + 4 * PAGE_BYTES);

    let mut damaged = bytes.clone();
    damaged[0..8].fill(0);
    let report = Lockbox::recover(damaged, KEY);
    assert_eq!(report.intact_file_count, 20);
}

#[test]
fn deleting_packed_file_redacts_original_page_and_preserves_other_files() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/packed/a.txt", b"alpha").unwrap();
    lb.put_file("/packed/b.txt", b"bravo").unwrap();
    lb.commit().unwrap();
    let before = lb.to_bytes();
    let packed_pages_before = count_pages(&before);

    lb.delete("/packed/a.txt").unwrap();
    lb.commit().unwrap();

    let after = lb.to_bytes();
    assert_eq!(
        Lockbox::open(after.clone(), KEY)
            .unwrap()
            .get_file("/packed/b.txt")
            .unwrap(),
        b"bravo"
    );
    assert!(matches!(
        Lockbox::open(after.clone(), KEY)
            .unwrap()
            .get_file("/packed/a.txt"),
        Err(Error::NotFound(_))
    ));
    assert!(count_pages(&after) >= packed_pages_before);
    assert!(page_offsets(&before)
        .into_iter()
        .any(|offset| after[offset..offset + 8].iter().all(|byte| *byte == 0)));
}

fn fill_randomish(buf: &mut [u8]) {
    for (i, byte) in buf.iter_mut().enumerate() {
        let mut value = i as u64;
        value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        *byte = (value ^ (value >> 31)) as u8;
    }
}

fn count_pages(bytes: &[u8]) -> usize {
    page_offsets(bytes).len()
}

fn page_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut index = 0usize;
    while index + 8 <= bytes.len() {
        if bytes.get(index..index + 8) == Some(b"LBX2PAG\0".as_slice()) {
            offsets.push(index);
            let next_metadata = index.saturating_add(METADATA_PAGE_BYTES);
            if next_metadata + 8 <= bytes.len()
                && bytes.get(next_metadata..next_metadata + 8) == Some(b"LBX2PAG\0".as_slice())
            {
                index = next_metadata;
            } else {
                index = index.saturating_add(PAGE_BYTES);
            }
        } else {
            index += 1;
        }
    }
    offsets
}

#[test]
fn manifest_round_trips_when_toc_payload_exceeds_minimum_page_body() {
    let mut lb = Lockbox::create(KEY);
    let payload = b"x";

    for i in 0..220 {
        let component = format!("file-{i:03}-{}.txt", "x".repeat(220));
        lb.put_file(&format!("/toc-overflow/{component}"), payload)
            .unwrap();
    }
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    let entries = reopened
        .list_iter(ListOptions {
            recursive: true,
            ..ListOptions::new("/toc-overflow")
        })
        .unwrap()
        .collect::<lockbox_core::Result<Vec<_>>>()
        .unwrap();

    assert_eq!(entries.len(), 220);
    assert!(reopened.to_bytes().len() > PAGE_BYTES);
    assert_eq!(
        reopened
            .get_file(&format!("/toc-overflow/file-219-{}.txt", "x".repeat(220)))
            .unwrap(),
        payload
    );
}

#[test]
fn toc_btree_create_round_trips_multiple_leaves() {
    let mut lb = Lockbox::create(KEY);
    for i in 0..300 {
        lb.put_file(&format!("/toc-create/file-{i:03}.txt"), b"create")
            .unwrap();
    }
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened
            .list_iter(ListOptions {
                recursive: true,
                ..ListOptions::new("/toc-create")
            })
            .unwrap()
            .count(),
        300
    );
    assert_eq!(
        reopened.get_file("/toc-create/file-299.txt").unwrap(),
        b"create"
    );
}

#[test]
fn toc_btree_append_round_trips_across_commits() {
    let mut lb = Lockbox::create(KEY);
    for i in 0..180 {
        lb.put_file(&format!("/toc-append/file-{i:03}.txt"), b"before")
            .unwrap();
    }
    lb.commit().unwrap();
    for i in 180..360 {
        lb.put_file(&format!("/toc-append/file-{i:03}.txt"), b"after")
            .unwrap();
    }
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened
            .list_iter(ListOptions {
                recursive: true,
                ..ListOptions::new("/toc-append")
            })
            .unwrap()
            .count(),
        360
    );
    assert_eq!(
        reopened.get_file("/toc-append/file-000.txt").unwrap(),
        b"before"
    );
    assert_eq!(
        reopened.get_file("/toc-append/file-359.txt").unwrap(),
        b"after"
    );
}

#[test]
fn toc_btree_delete_round_trips_across_commits() {
    let mut lb = Lockbox::create(KEY);
    for i in 0..300 {
        lb.put_file(&format!("/toc-delete/file-{i:03}.txt"), b"live")
            .unwrap();
    }
    lb.commit().unwrap();
    for i in (0..300).step_by(3) {
        lb.delete(&format!("/toc-delete/file-{i:03}.txt")).unwrap();
    }
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened
            .list_iter(ListOptions {
                recursive: true,
                ..ListOptions::new("/toc-delete")
            })
            .unwrap()
            .count(),
        200
    );
    assert!(matches!(
        reopened.get_file("/toc-delete/file-000.txt"),
        Err(Error::NotFound(_))
    ));
    assert_eq!(
        reopened.get_file("/toc-delete/file-001.txt").unwrap(),
        b"live"
    );
}

#[test]
fn appending_after_commit_preserves_existing_files() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.commit().unwrap();
    let len_after_first_commit = lb.to_bytes().len();

    lb.put_file("/docs/b.txt", b"bravo").unwrap();
    lb.commit().unwrap();

    assert!(lb.to_bytes().len() > len_after_first_commit);
    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file("/docs/a.txt").unwrap(), b"alpha");
    assert_eq!(reopened.get_file("/docs/b.txt").unwrap(), b"bravo");
    assert_eq!(reopened.list("/docs").unwrap().len(), 2);
}

#[test]
fn delete_removes_file_after_commit_and_reopen() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_file("/docs/b.txt", b"bravo").unwrap();
    lb.commit().unwrap();

    lb.delete("/docs/a.txt").unwrap();
    assert!(matches!(
        lb.get_file("/docs/a.txt"),
        Err(Error::NotFound(_))
    ));
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert!(matches!(
        reopened.get_file("/docs/a.txt"),
        Err(Error::NotFound(_))
    ));
    assert_eq!(reopened.get_file("/docs/b.txt").unwrap(), b"bravo");
    assert_eq!(reopened.list("/docs").unwrap().len(), 1);
}

#[test]
fn deleted_file_space_can_be_reused_by_appended_content() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/remove.bin", &[1; 1024]).unwrap();
    lb.commit().unwrap();
    let len_after_first_commit = lb.to_bytes().len();

    lb.delete("/docs/remove.bin").unwrap();
    lb.put_file("/docs/replacement.bin", &[2; 1024]).unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert!(matches!(
        reopened.get_file("/docs/remove.bin"),
        Err(Error::NotFound(_))
    ));
    assert_eq!(
        reopened.get_file("/docs/replacement.bin").unwrap(),
        [2; 1024]
    );
    assert!(reopened.to_bytes().len() <= len_after_first_commit + 5 * PAGE_BYTES);
}

#[test]
fn decoded_page_cache_records_hits_and_can_be_trimmed() {
    let mut lb = Lockbox::create_with_options(
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(128 * 1024 * 1024),
            ..LockboxOptions::default()
        },
    );
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.commit().unwrap();
    let reopened = Lockbox::open_with_options(
        lb.to_bytes(),
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(128 * 1024 * 1024),
            ..LockboxOptions::default()
        },
    )
    .unwrap();

    reopened.get_file("/docs/a.txt").unwrap();
    reopened.get_file("/docs/a.txt").unwrap();
    let stats = reopened.cache_stats();
    assert!(stats.entries > 0);
    assert!(stats.hits > 0);

    reopened.trim_cache();
    assert_eq!(reopened.cache_stats().entries, 0);
}

#[test]
fn decoded_page_cache_can_be_disabled() {
    let mut lb = Lockbox::create_with_options(
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Disabled,
            ..LockboxOptions::default()
        },
    );
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.commit().unwrap();

    lb.get_file("/docs/a.txt").unwrap();
    assert_eq!(lb.cache_stats().entries, 0);
    assert_eq!(lb.cache_stats().used_bytes, 0);
}

#[test]
fn bulk_import_flushes_file_pages_without_retaining_them_in_cache() {
    let mut data = vec![0; 2 * 1024 * 1024];
    fill_randomish(&mut data);
    let mut lb = Lockbox::create_with_options(
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(128 * 1024 * 1024),
            workload_profile: WorkloadProfile::BulkImport,
        },
    );

    lb.put_file("/bulk/data.zip", &data).unwrap();

    assert_eq!(lb.cache_stats().entries, 0);
    assert_eq!(lb.cache_stats().used_bytes, 0);
    assert!(lb.storage_len().unwrap() > HEADER_LEN as u64);
    assert_eq!(lb.get_file("/bulk/data.zip").unwrap(), data);
    assert!(lb.cache_stats().entries > 0);

    lb.commit().unwrap();
    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file("/bulk/data.zip").unwrap(), data);
}

#[test]
fn bulk_import_drains_small_file_staging_before_commit() {
    let data = vec![0xabu8; 25 * 1024];
    let mut lb = Lockbox::create_with_options(
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(128 * 1024 * 1024),
            workload_profile: WorkloadProfile::BulkImport,
        },
    );

    for index in 0..400 {
        lb.put_file(&format!("/bulk/small-{index:04}.zip"), &data)
            .unwrap();
    }

    assert!(lb.storage_len().unwrap() > HEADER_LEN as u64);
    assert_eq!(lb.cache_stats().entries, 0);
    assert_eq!(lb.get_file("/bulk/small-0000.zip").unwrap(), data);
    assert_eq!(lb.get_file("/bulk/small-0399.zip").unwrap(), data);

    lb.commit().unwrap();
    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file("/bulk/small-0000.zip").unwrap(), data);
    assert_eq!(reopened.get_file("/bulk/small-0399.zip").unwrap(), data);
}

#[test]
fn bulk_small_file_packer_keeps_non_tail_pages_dense() {
    let data = vec![0xabu8; 25 * 1024];
    let mut lb = Lockbox::create_with_options(
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(128 * 1024 * 1024),
            workload_profile: WorkloadProfile::BulkImport,
        },
    );

    for index in 0..700 {
        lb.put_file(&format!("/bulk/dense-{index:04}.zip"), &data)
            .unwrap();
    }
    lb.commit().unwrap();

    let file_pages = lb
        .inspect_pages()
        .unwrap()
        .into_iter()
        .filter(|page| page.objects.iter().any(|object| object.kind == "file-data"))
        .collect::<Vec<_>>();
    assert_eq!(file_pages.len(), 3);
    for page in file_pages.iter().take(file_pages.len() - 1) {
        assert!(
            page.object_count >= 300,
            "non-tail file page at offset {} only has {} objects",
            page.offset,
            page.object_count
        );
    }
}

#[test]
fn range_reads_are_clamped_to_file_bounds() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();

    assert_eq!(lb.read_file_range("/docs/a.txt", 0, 99).unwrap(), b"alpha");
    assert_eq!(lb.read_file_range("/docs/a.txt", 2, 99).unwrap(), b"pha");
    assert_eq!(lb.read_file_range("/docs/a.txt", 99, 10).unwrap(), b"");
}

#[test]
fn range_reads_only_return_requested_large_file_slice() {
    let mut lb = Lockbox::create(KEY);
    let content = vec![7u8; 8 * 1024 * 1024 + 512];
    lb.put_file("/large.bin", &content).unwrap();

    assert_eq!(
        lb.read_file_range("/large.bin", 8 * 1024 * 1024 - 4, 16)
            .unwrap(),
        content[8 * 1024 * 1024 - 4..8 * 1024 * 1024 + 12]
    );
}

#[test]
fn extract_all_enforces_file_count_limit() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_file("/docs/b.txt", b"bravo").unwrap();

    let policy = ExtractPolicy {
        max_files: 1,
        ..ExtractPolicy::default()
    };
    assert!(matches!(
        lb.extract_all(&policy),
        Err(Error::SecurityLimitExceeded(_))
    ));
}

#[test]
fn extract_all_enforces_single_file_size_limit() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();

    let policy = ExtractPolicy {
        max_file_bytes: 4,
        ..ExtractPolicy::default()
    };
    assert!(matches!(
        lb.extract_all(&policy),
        Err(Error::SecurityLimitExceeded(_))
    ));
}

#[test]
fn extract_all_enforces_total_size_limit() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_file("/docs/b.txt", b"bravo").unwrap();

    let policy = ExtractPolicy {
        max_total_bytes: 9,
        ..ExtractPolicy::default()
    };
    assert!(matches!(
        lb.extract_all(&policy),
        Err(Error::SecurityLimitExceeded(_))
    ));
}

#[test]
fn extract_all_returns_regular_files_when_within_limits() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_file("/docs/b.txt", b"bravo").unwrap();

    let extracted = lb.extract_all(&ExtractPolicy::default()).unwrap();
    assert_eq!(extracted.len(), 2);
    assert!(extracted
        .iter()
        .any(|file| file.path == "/docs/a.txt" && file.bytes == b"alpha"));
}

#[test]
fn extract_to_directory_refuses_overwrite_by_default() {
    let dir = std::env::temp_dir().join(format!("lockbox-extract-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("docs")).unwrap();
    std::fs::write(dir.join("docs/a.txt"), "existing").unwrap();

    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();

    assert!(matches!(
        lb.extract_to_directory(&dir, &ExtractPolicy::default()),
        Err(Error::SecurityLimitExceeded(_))
    ));

    let policy = ExtractPolicy {
        overwrite: true,
        ..ExtractPolicy::default()
    };
    lb.extract_to_directory(&dir, &policy).unwrap();
    assert_eq!(std::fs::read(dir.join("docs/a.txt")).unwrap(), b"alpha");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extract_to_directory_preflights_limits_before_writing_files() {
    let dir =
        std::env::temp_dir().join(format!("lockbox-extract-preflight-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_file("/docs/b.txt", b"bravo").unwrap();

    let policy = ExtractPolicy {
        max_total_bytes: 9,
        ..ExtractPolicy::default()
    };
    assert!(matches!(
        lb.extract_to_directory(&dir, &policy),
        Err(Error::SecurityLimitExceeded(_))
    ));
    assert!(!dir.join("docs/a.txt").exists());
    assert!(!dir.join("docs/b.txt").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn list_is_non_recursive() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_file("/docs/nested/b.txt", b"bravo").unwrap();
    lb.put_file("/other/c.txt", b"charlie").unwrap();

    let docs = lb.list("/docs").unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].path, "/docs/a.txt");
}

#[test]
fn list_iter_streams_entries_and_supports_rust_side_filtering() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_file("/docs/b.pdf", b"bravo").unwrap();
    lb.put_file("/docs/c.pdf", b"charlie").unwrap();

    let pdfs: Vec<_> = lb
        .list_iter(ListOptions::new("/docs"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path.ends_with(".pdf"))
        .collect();

    assert_eq!(pdfs.len(), 2);
    assert!(pdfs.iter().all(|entry| entry.kind == EntryKind::File));
}

#[test]
fn list_glob_filters_without_callback_bindings() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_file("/docs/b.pdf", b"bravo").unwrap();
    lb.put_file("/docs/nested/c.pdf", b"charlie").unwrap();

    let direct = lb.list_glob("/docs", "*.pdf").unwrap();
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0].path, "/docs/b.pdf");

    let recursive = lb.list_glob("/docs", "**/*.pdf").unwrap();
    assert_eq!(recursive.len(), 2);
}

#[test]
fn list_options_can_limit_and_filter_node_types() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_symlink("/docs/current", "/docs/a.txt").unwrap();

    let mut options = ListOptions::new("/docs");
    options.include_files = false;
    let links: Vec<_> = lb
        .list_iter(options)
        .unwrap()
        .collect::<lockbox_core::Result<_>>()
        .unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].kind, EntryKind::Symlink);
    assert_eq!(links[0].symlink_target.as_deref(), Some("/docs/a.txt"));

    let mut options = ListOptions::new("/docs");
    options.limit = Some(1);
    assert_eq!(lb.list_iter(options).unwrap().count(), 1);
}

#[test]
fn symlink_support_round_trips_and_safe_extraction_skips_by_default() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file_with_permissions("/docs/a.txt", b"alpha", 0o640)
        .unwrap();
    lb.put_symlink("/docs/current", "/docs/a.txt").unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert!(reopened.is_symlink("/docs/current"));
    assert_eq!(
        reopened.get_symlink_target("/docs/current").unwrap(),
        "/docs/a.txt"
    );
    assert_eq!(reopened.permissions("/docs/a.txt"), Some(0o640));

    let files = reopened.extract_all(&ExtractPolicy::default()).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].permissions, 0o640);

    let nodes = reopened
        .extract_all_nodes(&ExtractPolicy::default())
        .unwrap();
    assert_eq!(nodes.len(), 1);

    let policy = ExtractPolicy {
        restore_symlinks: true,
        ..ExtractPolicy::default()
    };
    let nodes = reopened.extract_all_nodes(&policy).unwrap();
    assert!(nodes.iter().any(|node| matches!(
        node,
        ExtractedNode::Symlink(link)
            if link.path == "/docs/current" && link.target == "/docs/a.txt"
    )));
}

#[test]
fn symlink_recovery_records_are_packed_into_metadata_pages() {
    let mut lb = Lockbox::create(KEY);
    for index in 0..50 {
        lb.put_symlink(
            &format!("/links/link-{index:02}"),
            &format!("/targets/target-{index:02}"),
        )
        .unwrap();
    }
    lb.commit().unwrap();

    let symlink_pages = lb
        .inspect_pages()
        .unwrap()
        .into_iter()
        .filter(|page| page.objects.iter().any(|object| object.kind == "symlink"))
        .count();
    assert_eq!(symlink_pages, 1);

    let mut damaged = lb.to_bytes();
    damaged[0] ^= 0xff;
    let report = Lockbox::recover(damaged, KEY);
    assert!(report.intact_files.iter().any(|entry| {
        entry.path == "/links/link-07"
            && entry.kind == EntryKind::Symlink
            && entry.symlink_target.as_deref() == Some("/targets/target-07")
    }));
}

#[test]
fn symlink_recovery_records_spill_across_metadata_pages() {
    let mut lb = Lockbox::create(KEY);
    for index in 0..1400 {
        lb.put_symlink(
            &format!("/links/{index:04}/{}", "l".repeat(40)),
            &format!("/targets/{index:04}/{}", "t".repeat(40)),
        )
        .unwrap();
    }
    lb.commit().unwrap();

    let symlink_pages = lb
        .inspect_pages()
        .unwrap()
        .into_iter()
        .filter(|page| page.objects.iter().any(|object| object.kind == "symlink"))
        .count();
    assert!(symlink_pages > 1, "expected spillover, got {symlink_pages}");

    let mut damaged = lb.to_bytes();
    damaged[0] ^= 0xff;
    let report = Lockbox::recover(damaged, KEY);
    let recovered = report
        .intact_files
        .iter()
        .filter(|entry| entry.kind == EntryKind::Symlink)
        .map(|entry| (entry.path.as_str(), entry.symlink_target.as_deref()))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(recovered.len(), 1400);
    for index in 0..1400 {
        let path = format!("/links/{index:04}/{}", "l".repeat(40));
        let target = format!("/targets/{index:04}/{}", "t".repeat(40));
        assert_eq!(
            recovered.get(path.as_str()).copied().flatten(),
            Some(target.as_str())
        );
    }
}

#[test]
fn invalid_permissions_are_rejected() {
    let mut lb = Lockbox::create(KEY);
    assert!(matches!(
        lb.put_file_with_permissions("/docs/a.txt", b"alpha", 0o1000),
        Err(Error::SecurityLimitExceeded(_))
    ));
}

#[test]
fn env_vars_round_trip_and_are_returned_as_a_map() {
    let mut lb = Lockbox::create(KEY);
    lb.set_env("DATABASE_URL", "postgres://localhost/app")
        .unwrap();
    lb.set_env("FEATURE_FLAG", "enabled").unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened.get_env("DATABASE_URL").unwrap().as_deref(),
        Some("postgres://localhost/app")
    );
    assert_eq!(
        reopened.list_env().unwrap(),
        vec!["DATABASE_URL".to_string(), "FEATURE_FLAG".to_string()]
    );
    assert_eq!(
        reopened
            .get_all_env()
            .unwrap()
            .get("FEATURE_FLAG")
            .map(String::as_str),
        Some("enabled")
    );
}

#[test]
fn env_vars_can_be_removed_and_replaced() {
    let mut lb = Lockbox::create(KEY);
    lb.set_env("TOKEN", "one").unwrap();
    lb.set_env("TOKEN", "two").unwrap();
    lb.set_env("REMOVE_ME", "gone").unwrap();
    lb.remove_env("REMOVE_ME").unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_env("TOKEN").unwrap().as_deref(), Some("two"));
    assert_eq!(reopened.get_env("REMOVE_ME").unwrap(), None);
}

#[test]
fn secret_env_vars_preserve_sensitivity_until_delete() {
    let mut lb = Lockbox::create(KEY);
    let first = password("first-secret");
    let second = password("second-secret");

    lb.set_secret_env("API_TOKEN", &first).unwrap();
    lb.commit().unwrap();

    let mut reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened.env_sensitivity("API_TOKEN").unwrap(),
        Some(lockbox_core::EnvSensitivity::Secret)
    );
    assert!(matches!(
        reopened.get_env("API_TOKEN"),
        Err(Error::SecurityLimitExceeded(_))
    ));
    assert_eq!(
        reopened
            .with_secret_env("API_TOKEN", str::to_string)
            .unwrap()
            .as_deref(),
        Some("first-secret")
    );
    assert!(!reopened.get_all_env().unwrap().contains_key("API_TOKEN"));
    assert!(matches!(
        reopened.set_env("API_TOKEN", "normal"),
        Err(Error::SecurityLimitExceeded(_))
    ));

    reopened.set_secret_env("API_TOKEN", &second).unwrap();
    reopened.commit().unwrap();
    let mut reopened = Lockbox::open(reopened.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened
            .with_secret_env("API_TOKEN", str::to_string)
            .unwrap()
            .as_deref(),
        Some("second-secret")
    );

    reopened.delete_env_var("API_TOKEN").unwrap();
    reopened.set_env("API_TOKEN", "normal").unwrap();
    assert_eq!(
        reopened.env_sensitivity("API_TOKEN").unwrap(),
        Some(lockbox_core::EnvSensitivity::Normal)
    );
    assert!(matches!(
        reopened.set_secret_env("API_TOKEN", &first),
        Err(Error::SecurityLimitExceeded(_))
    ));
}

#[test]
fn secret_env_access_caches_secure_decoded_page() {
    let mut lb = Lockbox::create_with_options(
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(128 * 1024 * 1024),
            ..LockboxOptions::default()
        },
    );
    let secret = password("cache-secret");
    lb.set_secret_env("API_TOKEN", &secret).unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open_with_options(
        lb.to_bytes(),
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(128 * 1024 * 1024),
            ..LockboxOptions::default()
        },
    )
    .unwrap();
    reopened.trim_cache();
    assert_eq!(reopened.cache_stats().entries, 0);

    assert_eq!(
        reopened
            .with_secret_env("API_TOKEN", str::to_string)
            .unwrap()
            .as_deref(),
        Some("cache-secret")
    );
    assert_eq!(reopened.cache_stats().entries, 1);

    assert_eq!(
        reopened.env_sensitivity("API_TOKEN").unwrap(),
        Some(lockbox_core::EnvSensitivity::Secret)
    );
    assert_eq!(reopened.cache_stats().entries, 1);
}

#[test]
fn many_env_vars_are_packed_into_leaf_pages() {
    let mut lb = Lockbox::create(KEY);
    for index in 0..200 {
        lb.set_env(&format!("VAR_{index:03}"), "value").unwrap();
    }
    lb.commit().unwrap();

    let env_leaf_pages = lb
        .inspect_pages()
        .unwrap()
        .into_iter()
        .filter(|page| page.objects.iter().any(|object| object.kind == "env-leaf"))
        .count();
    assert_eq!(env_leaf_pages, 1);

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.list_env().unwrap().len(), 200);
}

#[test]
fn removing_env_var_sanitizes_original_env_page() {
    let mut lb = Lockbox::create(KEY);
    lb.set_env("KEEP_ME", "still-here").unwrap();
    lb.set_env("REMOVE_ME", "gone").unwrap();
    lb.commit().unwrap();
    let original_env_offset = lb
        .inspect_pages()
        .unwrap()
        .into_iter()
        .find(|page| page.objects.iter().any(|object| object.kind == "env-leaf"))
        .unwrap()
        .offset;

    lb.remove_env("REMOVE_ME").unwrap();
    lb.commit().unwrap();

    let after = lb.to_bytes();
    let reopened = Lockbox::open(after.clone(), KEY).unwrap();
    assert_eq!(
        reopened.get_env("KEEP_ME").unwrap().as_deref(),
        Some("still-here")
    );
    assert_eq!(reopened.get_env("REMOVE_ME").unwrap(), None);
    assert!(lb
        .inspect_pages()
        .unwrap()
        .into_iter()
        .any(|page| page.offset == original_env_offset
            && page
                .objects
                .iter()
                .any(|object| object.kind == "env-leaf" && object.payload_len <= 6)));
}

#[test]
fn env_names_and_values_are_validated() {
    let mut lb = Lockbox::create(KEY);

    for name in ["", "1BAD", "BAD-NAME", "BAD.NAME", "BAD NAME"] {
        assert!(
            matches!(lb.set_env(name, "value"), Err(Error::InvalidPath(_))),
            "env name should be rejected: {name:?}"
        );
    }

    assert!(matches!(
        lb.set_env("BAD_VALUE", "has\0nul"),
        Err(Error::SecurityLimitExceeded(_))
    ));
}

#[test]
fn env_vars_are_private_and_do_not_appear_in_listings() {
    let mut lb = Lockbox::create(KEY);
    lb.set_env("SECRET_TOKEN", "super-secret").unwrap();
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.commit().unwrap();

    let bytes = lb.to_bytes();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("SECRET_TOKEN"));
    assert!(!text.contains("super-secret"));

    let reopened = Lockbox::open(bytes, KEY).unwrap();
    assert_eq!(reopened.list("/docs").unwrap().len(), 1);
}

#[test]
fn delete_and_rename_update_the_manifest() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_file("/docs/b.txt", b"bravo").unwrap();
    lb.rename("/docs/b.txt", "/docs/c.txt").unwrap();
    lb.delete("/docs/a.txt").unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert!(matches!(
        reopened.get_file("/docs/a.txt"),
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        reopened.get_file("/docs/b.txt"),
        Err(Error::NotFound(_))
    ));
    assert_eq!(reopened.get_file("/docs/c.txt").unwrap(), b"bravo");
}

#[test]
fn rename_moves_directory_prefixes() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_file("/docs/sub/b.txt", b"bravo").unwrap();
    lb.put_file("/other/keep.txt", b"keep").unwrap();

    lb.rename("/docs", "/archive/docs").unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert!(matches!(
        reopened.get_file("/docs/a.txt"),
        Err(Error::NotFound(_))
    ));
    assert_eq!(reopened.get_file("/archive/docs/a.txt").unwrap(), b"alpha");
    assert_eq!(
        reopened.get_file("/archive/docs/sub/b.txt").unwrap(),
        b"bravo"
    );
    assert_eq!(reopened.get_file("/other/keep.txt").unwrap(), b"keep");
}

#[test]
fn rename_moves_symlinks_inside_directory_prefixes() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/current.txt", b"current").unwrap();
    lb.put_symlink("/docs/link.txt", "/docs/current.txt")
        .unwrap();

    lb.rename("/docs", "/archive").unwrap();

    assert_eq!(lb.get_file("/archive/current.txt").unwrap(), b"current");
    assert_eq!(
        lb.get_symlink_target("/archive/link.txt").unwrap(),
        "/docs/current.txt"
    );
    assert!(!lb.is_symlink("/docs/link.txt"));
    assert!(lb.is_symlink("/archive/link.txt"));
}

#[test]
fn rename_rejects_missing_directory_prefix_and_self_nested_moves() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();

    assert!(matches!(
        lb.rename("/missing", "/archive"),
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        lb.rename("/docs", "/docs/archive"),
        Err(Error::InvalidPath(_))
    ));
}

#[test]
fn replacing_a_file_updates_content_and_keeps_old_version_out_of_manifest() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"version one").unwrap();
    lb.commit().unwrap();

    lb.put_file("/docs/a.txt", b"version two").unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file("/docs/a.txt").unwrap(), b"version two");
    assert_eq!(reopened.list("/docs").unwrap().len(), 1);
}

#[test]
fn reuses_deleted_record_space_when_possible() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/large.txt", &[7; 2 * 1024 * 1024])
        .unwrap();
    lb.commit().unwrap();
    let after_large = lb.to_bytes().len();

    lb.delete("/docs/large.txt").unwrap();
    lb.put_file("/docs/small.txt", b"small").unwrap();
    lb.commit().unwrap();
    let after_reuse = lb.to_bytes().len();

    assert!(after_reuse <= after_large + 5 * PAGE_BYTES);
    assert_eq!(lb.get_file("/docs/small.txt").unwrap(), b"small");
}

#[test]
fn reused_space_does_not_leak_old_file_path_or_content() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/secret/old-name.txt", &[b'x'; 2048]).unwrap();
    lb.commit().unwrap();

    lb.delete("/secret/old-name.txt").unwrap();
    lb.put_file("/public/new-name.txt", b"new").unwrap();
    lb.commit().unwrap();

    let bytes = lb.to_bytes();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("/secret/old-name.txt"));
    assert!(!text.contains("/public/new-name.txt"));
}

#[test]
fn recovery_survives_corrupt_header() {
    let bytes = sample_lockbox();
    let mut damaged = bytes.clone();
    damaged[0] ^= 0xff;

    assert!(Lockbox::open(damaged.clone(), KEY).is_err());

    let report = Lockbox::recover(damaged, KEY);
    assert_eq!(report.intact_file_count, 3);
    assert_eq!(report.partial_files, 0);
    assert!(!report.manifest_recovered);
    assert!(report.intact_files.iter().any(|e| e.path == "/docs/a.txt"));
}

#[test]
fn recovery_survives_header_manifest_pointer_zeroed() {
    let mut damaged = sample_lockbox();
    damaged[16..24].fill(0);
    update_test_header_checksum(&mut damaged);

    let opened = Lockbox::open(damaged.clone(), KEY).unwrap();
    assert_eq!(opened.get_file("/docs/a.txt").unwrap(), b"alpha");

    let report = Lockbox::recover(damaged, KEY);
    assert_eq!(report.intact_file_count, 3);
    assert!(!report.manifest_recovered);
}

#[test]
fn open_uses_previous_commit_when_latest_commit_root_is_corrupt() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/old.txt", b"old").unwrap();
    lb.commit().unwrap();
    let previous = lb.to_bytes();

    lb.put_file("/docs/new.txt", b"new").unwrap();
    lb.commit().unwrap();
    let mut damaged = lb.to_bytes();
    let latest_root = u64::from_le_bytes(damaged[16..24].try_into().unwrap()) as usize;
    damaged[latest_root + 55] ^= 0xaa;

    let opened = Lockbox::open(damaged, KEY).unwrap();
    assert_eq!(opened.get_file("/docs/old.txt").unwrap(), b"old");
    assert!(matches!(
        opened.get_file("/docs/new.txt"),
        Err(Error::NotFound(_))
    ));
    assert_eq!(
        Lockbox::open(previous, KEY)
            .unwrap()
            .get_file("/docs/old.txt")
            .unwrap(),
        b"old"
    );
}

#[test]
fn stale_header_after_interrupted_commit_opens_last_published_state() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/old.txt", b"old").unwrap();
    lb.commit().unwrap();
    let previous = lb.to_bytes();

    lb.put_file("/docs/new.txt", b"new").unwrap();
    lb.commit().unwrap();
    let mut interrupted = lb.to_bytes();
    interrupted[0..HEADER_LEN].copy_from_slice(&previous[0..HEADER_LEN]);

    let opened = Lockbox::open(interrupted, KEY).unwrap();
    assert_eq!(opened.get_file("/docs/old.txt").unwrap(), b"old");
    assert!(matches!(
        opened.get_file("/docs/new.txt"),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn recovery_survives_corrupt_manifest_record() {
    let bytes = sample_lockbox();
    let lb = Lockbox::open(bytes.clone(), KEY).unwrap();
    let mut damaged = bytes;

    let header_manifest_offset = u64::from_le_bytes(damaged[16..24].try_into().unwrap()) as usize;
    damaged[header_manifest_offset + 55] ^= 0x55;

    assert!(Lockbox::open(damaged.clone(), KEY).is_err());

    let report = Lockbox::recover(damaged, KEY);
    assert_eq!(report.intact_file_count, 3);
    assert_eq!(report.partial_files, 0);
    assert!(!report.manifest_recovered);
    assert_eq!(lb.get_file("/docs/a.txt").unwrap(), b"alpha");
}

#[test]
fn recovery_ignores_deleted_files_when_rebuilding_without_manifest() {
    let mut lb = Lockbox::create(KEY);
    lb.put_file("/docs/a.txt", b"alpha").unwrap();
    lb.put_file("/docs/delete-me.txt", b"delete").unwrap();
    lb.delete("/docs/delete-me.txt").unwrap();
    lb.commit().unwrap();

    let mut damaged = lb.to_bytes();
    let header_manifest_offset = u64::from_le_bytes(damaged[16..24].try_into().unwrap()) as usize;
    damaged[header_manifest_offset + 55] ^= 0x55;

    let report = Lockbox::recover(damaged, KEY);
    assert_eq!(report.intact_file_count, 1);
    assert!(report
        .intact_files
        .iter()
        .all(|entry| entry.path != "/docs/delete-me.txt"));
}

#[test]
fn recovery_reports_partial_when_file_record_is_corrupt_but_manifest_survives() {
    let bytes = sample_lockbox();
    let lb = Lockbox::open(bytes.clone(), KEY).unwrap();
    let mut damaged = bytes;

    let entry = lb.stat("/docs/a.txt").unwrap();
    assert_eq!(entry.len, 5);
    let first_record_offset = 64usize;
    damaged[first_record_offset + 55] ^= 0xaa;

    let report = Lockbox::recover(damaged, KEY);
    assert!(report.manifest_recovered);
    assert_eq!(report.intact_file_count, 2);
    assert_eq!(report.partial_files, 1);
    assert!(report.intact_files.iter().any(|e| e.path == "/docs/a.txt"));
}

#[test]
fn recovery_reports_corrupt_records_for_damaged_frame_header() {
    let mut damaged = sample_lockbox();
    damaged[64 + 44] ^= 0x11;

    let report = Lockbox::recover(damaged, KEY);
    assert!(report.corrupt_records > 0);
    assert_eq!(report.partial_files, 1);
}

#[test]
fn recovery_skips_truncated_tail_and_keeps_prior_intact_files() {
    let mut damaged = sample_lockbox();
    let last_page = page_offsets(&damaged).into_iter().last().unwrap();
    let header_len =
        u32::from_le_bytes(damaged[last_page + 12..last_page + 16].try_into().unwrap()) as usize;
    let encrypted_len =
        u32::from_le_bytes(damaged[last_page + 44..last_page + 48].try_into().unwrap()) as usize;
    damaged.truncate(last_page + header_len + encrypted_len - 1);

    let report = Lockbox::recover(damaged, KEY);
    assert_eq!(report.intact_file_count, 3);
    assert!(!report.manifest_recovered);
}

#[test]
fn salvage_writes_intact_files_to_a_clean_lockbox() {
    let bytes = sample_lockbox();
    let mut damaged = bytes;
    damaged[0] ^= 0xff;

    let salvaged = Lockbox::salvage(damaged, KEY).unwrap();
    assert_eq!(salvaged.get_file("/docs/a.txt").unwrap(), b"alpha");
    assert_eq!(salvaged.get_file("/docs/b.txt").unwrap(), b"bravo");
    assert_eq!(salvaged.get_file("/photos/c.jpg").unwrap(), b"image");
}

#[test]
fn salvage_omits_corrupt_file_records() {
    let mut damaged = sample_lockbox();
    damaged[64 + 55] ^= 0xaa;

    let salvaged = Lockbox::salvage(damaged, KEY).unwrap();
    assert!(matches!(
        salvaged.get_file("/docs/a.txt"),
        Err(Error::NotFound(_))
    ));
    assert_eq!(salvaged.get_file("/docs/b.txt").unwrap(), b"bravo");
    assert_eq!(salvaged.get_file("/photos/c.jpg").unwrap(), b"image");
}

#[test]
fn wrong_key_cannot_open_or_recover_private_metadata() {
    let bytes = sample_lockbox();
    assert!(Lockbox::open(bytes.clone(), b"wrong key").is_err());

    let report = Lockbox::recover(bytes, b"wrong key");
    assert_eq!(report.intact_file_count, 0);
    assert_eq!(report.intact_files.len(), 0);
}

#[test]
fn committed_file_names_and_content_are_not_visible_in_cleartext() {
    let bytes = sample_lockbox();
    let text = String::from_utf8_lossy(&bytes);

    for needle in [
        "/docs/a.txt",
        "/docs/b.txt",
        "/photos/c.jpg",
        "alpha",
        "bravo",
        "image",
    ] {
        assert!(!text.contains(needle), "cleartext leak: {needle}");
    }
}

#[test]
fn many_files_round_trip_and_recover_after_manifest_loss() {
    let mut lb = Lockbox::create(KEY);
    for i in 0..100 {
        let path = format!("/many/file-{i:03}.txt");
        let content = format!("content-{i:03}");
        lb.put_file(&path, content.as_bytes()).unwrap();
    }
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.list("/many").unwrap().len(), 100);
    assert_eq!(
        reopened.get_file("/many/file-042.txt").unwrap(),
        b"content-042"
    );

    let mut damaged = reopened.to_bytes();
    let header_manifest_offset = u64::from_le_bytes(damaged[16..24].try_into().unwrap()) as usize;
    damaged[header_manifest_offset + 55] ^= 0x55;
    let report = Lockbox::recover(damaged, KEY);
    assert_eq!(report.intact_file_count, 100);
}

#[test]
fn recovery_report_default_summarizes_intact_files_without_listing_them() {
    let report = Lockbox::recover(sample_lockbox(), KEY);
    let rendered = report.render(&RecoveryReportOptions::default());

    assert!(rendered.contains("Intact files: 3"));
    assert!(!rendered.contains("/docs/a.txt"));
    assert!(!rendered.contains("Intact:\n  /docs/a.txt"));
}

#[test]
fn recovery_report_verbose_lists_intact_files_with_optional_limit() {
    let report = Lockbox::recover(sample_lockbox(), KEY);
    let rendered = report.render(&RecoveryReportOptions {
        verbose: true,
        max_intact_entries: Some(2),
    });

    assert!(rendered.contains("Intact:\n"));
    assert!(rendered.contains("/docs/a.txt"));
    assert!(rendered.contains("1 more intact files omitted"));
}

#[test]
fn large_file_rename_is_metadata_only_and_survives_reopen() {
    let mut lb = Lockbox::create(KEY);
    let payload = vec![0x5au8; 12 * 1024 * 1024];
    lb.put_file_from_reader("/large/source.bin", Cursor::new(&payload))
        .unwrap();
    lb.commit().unwrap();
    let before = lb.to_bytes().len();

    lb.rename("/large/source.bin", "/archive/renamed.bin")
        .unwrap();
    lb.commit().unwrap();
    let after = lb.to_bytes().len();

    assert!(
        after <= before + 4 * PAGE_BYTES,
        "rename rewrote too much data: before={before}, after={after}"
    );
    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert!(matches!(
        reopened.get_file("/large/source.bin"),
        Err(Error::NotFound(_))
    ));
    assert_eq!(reopened.get_file("/archive/renamed.bin").unwrap(), payload);

    let report = Lockbox::recover(lb.to_bytes(), KEY);
    assert_eq!(report.intact_file_count, 1);
    assert!(report
        .intact_files
        .iter()
        .any(|file| file.path == "/archive/renamed.bin"));
}

#[test]
fn compact_preserves_large_file_after_streaming_rewrite() {
    let mut lb = Lockbox::create(KEY);
    let payload = vec![0x7bu8; 10 * 1024 * 1024];
    lb.put_file_from_reader("/large/blob.bin", Cursor::new(&payload))
        .unwrap();
    lb.put_file("/small.txt", b"small").unwrap();
    lb.commit().unwrap();

    lb.delete("/small.txt").unwrap();
    lb.compact().unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file("/large/blob.bin").unwrap(), payload);
    assert!(matches!(
        reopened.get_file("/small.txt"),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn path_backed_compact_logically_rewrites_live_state() {
    let path = temp_path("path-backed-logical-compact");
    let payload = vec![0x51u8; PAGE_BYTES + 123];
    let _ = std::fs::remove_file(&path);

    let mut lb = Lockbox::create_path(&path, KEY).unwrap();
    lb.put_file_from_reader("/large/blob.bin", Cursor::new(&payload))
        .unwrap();
    lb.put_file("/empty.bin", b"").unwrap();
    lb.put_file("/stale.txt", b"remove me").unwrap();
    lb.put_symlink("/links/current", "/large/blob.bin").unwrap();
    lb.set_env("TOKEN", "old").unwrap();
    lb.commit().unwrap();

    lb.delete("/stale.txt").unwrap();
    lb.set_env("TOKEN", "new").unwrap();
    lb.compact().unwrap();

    let reopened = Lockbox::open_path(&path, KEY).unwrap();
    assert_eq!(reopened.get_file("/large/blob.bin").unwrap(), payload);
    assert_eq!(reopened.get_file("/empty.bin").unwrap(), b"");
    assert_eq!(
        reopened.get_symlink_target("/links/current").unwrap(),
        "/large/blob.bin"
    );
    assert_eq!(reopened.get_env("TOKEN").unwrap().as_deref(), Some("new"));
    assert!(matches!(
        reopened.get_file("/stale.txt"),
        Err(Error::NotFound(_))
    ));

    let _ = std::fs::remove_file(path);
}

fn sample_lockbox() -> Vec<u8> {
    let mut lb = Lockbox::create(KEY);
    lb.put_file_from_reader("/docs/a.txt", Cursor::new(b"alpha"))
        .unwrap();
    lb.put_file_from_reader("/docs/b.txt", Cursor::new(b"bravo"))
        .unwrap();
    lb.put_file_from_reader("/photos/c.jpg", Cursor::new(b"image"))
        .unwrap();
    lb.commit().unwrap();
    lb.to_bytes()
}

fn update_test_header_checksum(bytes: &mut [u8]) {
    let mut hasher = Sha256::new();
    hasher.update(b"lockbox-v2-public-checksum/sha256");
    hasher.update((HEADER_CHECKSUM_START as u64).to_le_bytes());
    hasher.update(&bytes[0..HEADER_CHECKSUM_START]);
    let digest = hasher.finalize();
    bytes[HEADER_CHECKSUM_START..HEADER_LEN].copy_from_slice(&digest);
}

fn temp_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "lockbox-core-{label}-{}-{}.lbox",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn password(value: &str) -> SecretString {
    SecretString::try_from_bytes(value.as_bytes().to_vec()).unwrap()
}
