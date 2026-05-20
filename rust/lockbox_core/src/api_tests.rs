use crate::{
    CacheLimit, EnvName, EnvSensitivity, EnvValueRef, Error, ExtractPolicy, ListOptions, Lockbox,
    LockboxEntry, LockboxEntryKind, LockboxKeySlotAlgorithm, LockboxKeySlotProtection,
    LockboxOptions, LockboxPath, LockboxProtection, LockboxUnlock, RecipientKeyPair,
    RecipientPublicKey, RecoveryReportOptions, RecoveryScanner, Result, SecretString,
    WorkloadProfile,
};
use sha2::{Digest, Sha256};
use std::io::Cursor;

const KEY: &[u8] = b"correct horse battery staple";
const HEADER_LEN: usize = 96;
const HEADER_CHECKSUM_START: usize = 64;
const PAGE_BYTES: usize = 8 * 1024 * 1024;
const PAGE_QUANTUM_BYTES: usize = 1024;

fn p(path: impl AsRef<str>) -> LockboxPath {
    LockboxPath::new(path).unwrap()
}

fn env(name: impl AsRef<str>) -> EnvName {
    EnvName::new(name).unwrap()
}

#[test]
fn create_put_get_list_stat_commit_open() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/b.txt"), b"bravo", false).unwrap();

    assert_eq!(lb.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
    assert_eq!(lb.read_file_range(&p("/docs/b.txt"), 1, 3).unwrap(), b"rav");
    assert_eq!(
        lb.stat(&p("/docs/a.txt")),
        Some(LockboxEntry {
            path: p("/docs/a.txt"),
            kind: LockboxEntryKind::File,
            len: 5,
            permissions: 0o600,
        })
    );

    assert_eq!(lb.list(ListOptions::new(&p("/docs"))).unwrap().count(), 2);

    lb.commit().unwrap();
    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
    assert_eq!(reopened.get_file(&p("/docs/b.txt")).unwrap(), b"bravo");
}

#[test]
fn write_to_path_and_open_path_round_trip() {
    let path = std::env::temp_dir().join(format!("lockbox-path-{}.lbx", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.commit().unwrap();
    lb.write_to_path(&path).unwrap();

    let reopened = Lockbox::open_path(&path, KEY).unwrap();
    assert_eq!(reopened.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
    assert_eq!(reopened.to_bytes(), std::fs::read(&path).unwrap());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_path_writes_file_backed_lockbox() {
    let path = std::env::temp_dir().join(format!("lockbox-create-path-{}.lbx", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let mut lb = Lockbox::create_path(&path, KEY).unwrap();
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.commit().unwrap();

    let bytes_on_disk = std::fs::read(&path).unwrap();
    assert_eq!(
        Lockbox::open(bytes_on_disk.clone(), KEY)
            .unwrap()
            .get_file(&p("/docs/a.txt"))
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

    lb.add_file(&p("/tiny.txt"), b"x", false).unwrap();

    assert_eq!(lb.to_bytes().len(), before);
    assert_eq!(lb.get_file(&p("/tiny.txt")).unwrap(), b"x");

    lb.commit().unwrap();
    let after = lb.to_bytes().len();

    assert!(after - before <= 4 * PAGE_BYTES);
    assert_eq!(lb.get_file(&p("/tiny.txt")).unwrap(), b"x");
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
    lb.add_file_from_path(&source, &p("/from-disk.txt"), false)
        .unwrap();

    assert_eq!(lb.to_bytes().len(), before);
    assert_eq!(
        lb.get_file(&p("/from-disk.txt")).unwrap(),
        b"tiny source file"
    );

    lb.commit().unwrap();
    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened.get_file(&p("/from-disk.txt")).unwrap(),
        b"tiny source file"
    );

    let _ = std::fs::remove_file(&source);
}

#[test]
fn small_env_pages_use_variable_page_quantum() {
    let mut lb = Lockbox::create(KEY);
    let before = lb.to_bytes().len();

    lb.set_env(&env("TOKEN"), "x").unwrap();

    lb.commit().unwrap();
    let env_page = lb
        .inspector()
        .inspect_pages()
        .unwrap()
        .into_iter()
        .find(|page| {
            page.objects
                .iter()
                .any(|object| object.kind == "env-leaf" && object.payload_len > 0)
        })
        .unwrap();
    assert!(env_page.page_size as usize >= PAGE_QUANTUM_BYTES);
    assert_eq!(env_page.page_size as usize % PAGE_QUANTUM_BYTES, 0);
    assert!(env_page.unused_bytes < env_page.page_size);
    assert!(lb.inspector().inspect_pages().unwrap().iter().any(|page| {
        page.objects
            .iter()
            .any(|object| object.kind == "env-leaf" && object.payload_len > 0)
    }));
    let after = lb.to_bytes().len();

    assert!(after > before);
    assert_eq!(lb.get_env(&env("TOKEN")).unwrap().as_deref(), Some("x"));
}

#[test]
fn env_scan_fails_closed_when_env_page_is_corrupt() {
    let mut lb = Lockbox::create(KEY);
    lb.set_env(&env("TOKEN"), "x").unwrap();
    lb.commit().unwrap();

    let env_page = lb
        .inspector()
        .inspect_pages()
        .unwrap()
        .into_iter()
        .find(|page| page.objects.iter().any(|object| object.kind == "env-leaf"))
        .unwrap();
    let mut bytes = lb.to_bytes();
    bytes[env_page.offset as usize + HEADER_LEN + 8] ^= 0x55;

    let reopened = Lockbox::open(bytes, KEY).unwrap();
    assert!(reopened.get_env(&env("TOKEN")).is_err());
}

#[test]
fn invalid_paths_are_rejected() {
    for path in [
        "",
        "relative.txt",
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
            matches!(LockboxPath::new(path), Err(Error::InvalidPath(_))),
            "path should be rejected: {path:?}"
        );
    }

    assert!(matches!(
        LockboxPath::new("relative"),
        Err(Error::InvalidPath(_))
    ));
    assert!(matches!(
        LockboxPath::new("/safe/.."),
        Err(Error::InvalidPath(_))
    ));

    let mut lb = Lockbox::create(KEY);
    for path in ["/", "/dir/"] {
        let path = LockboxPath::new(path).expect("directory lockbox path should be valid");
        assert!(
            matches!(lb.add_file(&path, b"x", false), Err(Error::InvalidPath(_))),
            "file API should reject directory-only path: {path:?}"
        );
    }
}

#[test]
fn add_file_requires_explicit_replace_intent() {
    let mut lb = Lockbox::create(KEY);
    let path = p("/docs/a.txt");

    assert!(!lb.exists(&path));
    assert!(matches!(
        lb.add_file(&path, b"missing", true),
        Err(Error::NotFound(_))
    ));

    lb.add_file(&path, b"alpha", false).unwrap();
    assert!(lb.exists(&path));
    assert!(matches!(
        lb.add_file(&path, b"bravo", false),
        Err(Error::AlreadyExists(_))
    ));

    lb.add_file(&path, b"bravo", true).unwrap();
    assert_eq!(lb.get_file(&path).unwrap(), b"bravo");
}

#[test]
fn path_depth_and_length_limits_are_enforced() {
    let too_deep = format!("/{}", vec!["x"; 65].join("/"));
    let too_long = format!("/{}", "a".repeat(4097));

    assert!(matches!(
        LockboxPath::new(&too_deep),
        Err(Error::InvalidPath(_))
    ));
    assert!(matches!(
        LockboxPath::new(&too_long),
        Err(Error::InvalidPath(_))
    ));
}

#[test]
fn unicode_paths_round_trip() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/résumé.pdf"), b"cv", false).unwrap();
    lb.add_file(&p("/写真/旅行.jpg"), b"photo", false).unwrap();
    lb.add_file(&p("/客户/合同.txt"), b"contract", false)
        .unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file(&p("/docs/résumé.pdf")).unwrap(), b"cv");
    assert_eq!(reopened.get_file(&p("/写真/旅行.jpg")).unwrap(), b"photo");
    assert_eq!(
        reopened.get_file(&p("/客户/合同.txt")).unwrap(),
        b"contract"
    );
}

#[test]
fn unicode_paths_are_canonicalized_to_nfc_for_storage_and_lookup() {
    let mut lb = Lockbox::create(KEY);
    let decomposed = "/docs/re\u{0301}sume\u{0301}.pdf";
    let composed = "/docs/résumé.pdf";

    lb.add_file(&p(decomposed), b"cv", false).unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file(&p(composed)).unwrap(), b"cv");
    assert_eq!(reopened.get_file(&p(decomposed)).unwrap(), b"cv");
    assert!(reopened.stat(&p(composed)).is_some());
    let listed = reopened
        .list(ListOptions::new(&p("/docs")))
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(listed[0].path, composed);
}

#[test]
fn unicode_normalization_collisions_replace_same_lockbox_path() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/re\u{0301}sume\u{0301}.pdf"), b"one", false)
        .unwrap();
    lb.add_file(&p("/docs/résumé.pdf"), b"two", true).unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file(&p("/docs/résumé.pdf")).unwrap(), b"two");
    assert_eq!(
        reopened
            .list(ListOptions::new(&p("/docs")))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn unicode_bidi_and_invisible_controls_are_rejected() {
    for path in [
        "/docs/report\u{202e}fdp.txt",
        "/docs/report\u{2066}.txt",
        "/docs/zero\u{200b}width.txt",
        "/docs/joiner\u{200d}.txt",
        "/docs/variation\u{fe0f}.txt",
        "/docs/c1\u{0085}.txt",
    ] {
        assert!(
            matches!(LockboxPath::new(path), Err(Error::InvalidPath(_))),
            "path should be rejected: {path:?}"
        );
    }
}

#[test]
fn empty_and_large_files_round_trip() {
    let large: Vec<u8> = (0..128_000).map(|i| (i % 251) as u8).collect();
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/empty.bin"), b"", false).unwrap();
    lb.add_file(&p("/large.bin"), &large, false).unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file(&p("/empty.bin")).unwrap(), b"");
    assert_eq!(reopened.get_file(&p("/large.bin")).unwrap(), large);
    assert_eq!(
        reopened
            .read_file_range(&p("/large.bin"), 12_345, 100)
            .unwrap(),
        large[12_345..12_445]
    );
}

#[test]
fn file_content_can_be_loaded_and_extracted_with_streaming_apis() {
    let mut lb = Lockbox::create(KEY);
    let content = vec![42u8; 8 * 1024 * 1024 + 123];

    lb.add_file_from_reader(&p("/large/stream.bin"), Cursor::new(&content), false)
        .unwrap();

    let mut extracted = Vec::new();
    lb.extract_file_to_writer(&p("/large/stream.bin"), &mut extracted)
        .unwrap();
    assert_eq!(extracted, content);
}

#[test]
fn content_keys_can_be_wrapped_with_ml_kem_1024() {
    let key_pair = RecipientKeyPair::generate().unwrap();
    let content_key = [9u8; 32];

    let wrapped = key_pair.encrypt(&content_key).unwrap();
    let unwrapped = key_pair.decrypt(&wrapped).unwrap();

    assert_eq!(unwrapped, content_key);
    assert!(!wrapped.encrypted_key().is_empty());
}

#[test]
fn ml_kem_wraps_for_same_recipient_do_not_share_ciphertext() {
    let key_pair = RecipientKeyPair::generate().unwrap();
    let content_key = [9u8; 32];

    let first = key_pair.encrypt(&content_key).unwrap();
    let second = key_pair.encrypt(&content_key).unwrap();

    assert_ne!(first.ciphertext_bytes(), second.ciphertext_bytes());
    assert_eq!(key_pair.decrypt(&first).unwrap(), content_key);
    assert_eq!(key_pair.decrypt(&second).unwrap(), content_key);
}

#[test]
fn password_slots_unlock_the_random_content_key() {
    let share_password = password("share-password");
    let mut lb = Lockbox::create_with_password(&share_password).unwrap();
    let lockbox_id = lb.lockbox_id();
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.commit().unwrap();

    let bytes = lb.to_bytes();
    assert!(matches!(
        Lockbox::open_with_password(bytes.clone(), &password("wrong-password")),
        Err(Error::InvalidKey)
    ));

    let reopened = Lockbox::open_with_password(bytes, &share_password).unwrap();
    assert_eq!(reopened.lockbox_id(), lockbox_id);
    assert_eq!(reopened.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
    let slot = &reopened.list_key_slots()[0];
    assert_eq!(slot.protection, LockboxKeySlotProtection::Password);
    assert_eq!(
        slot.algorithm,
        LockboxKeySlotAlgorithm::Argon2idChaCha20Poly1305
    );
}

#[test]
fn password_unlock_recovers_when_header_is_corrupt() {
    let share_password = password("share-password");
    let mut lb = Lockbox::create_with_password(&share_password).unwrap();
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.commit().unwrap();

    let mut bytes = lb.to_bytes();
    bytes[0] ^= 0xff;

    let reopened = Lockbox::open_with_password(bytes, &share_password).unwrap();
    assert_eq!(reopened.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
}

#[test]
fn password_unlock_recovers_when_primary_key_directory_is_corrupt() {
    let share_password = password("share-password");
    let mut lb = Lockbox::create_with_password(&share_password).unwrap();
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.commit().unwrap();

    let mut bytes = lb.to_bytes();
    let primary_key_directory_offset =
        u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    bytes[primary_key_directory_offset] ^= 0xff;

    let reopened = Lockbox::open_with_password(bytes, &share_password).unwrap();
    assert_eq!(reopened.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
}

#[test]
fn multiple_key_slots_are_tried_until_one_unlocks() {
    let alice = RecipientKeyPair::generate().unwrap();
    let bob = RecipientKeyPair::generate().unwrap();
    let outsider = RecipientKeyPair::generate().unwrap();
    let bob_public = RecipientPublicKey::from_bytes(&bob.public_key().to_bytes()).unwrap();

    let mut lb = Lockbox::create_with_recipient(&alice.public_key()).unwrap();
    lb.add_recipient(&bob_public).unwrap();
    let backup_password = password("backup-password");
    lb.add_password(&backup_password).unwrap();
    lb.add_file(&p("/shared/report.txt"), b"report", false)
        .unwrap();
    lb.commit().unwrap();

    let bytes = lb.to_bytes();
    assert!(matches!(
        Lockbox::open_with_recipient(bytes.clone(), &outsider),
        Err(Error::InvalidKey)
    ));

    let by_bob = Lockbox::open_with_recipient(bytes.clone(), &bob).unwrap();
    assert_eq!(
        by_bob.get_file(&p("/shared/report.txt")).unwrap(),
        b"report"
    );

    let by_password = Lockbox::open_with_password(bytes, &backup_password).unwrap();
    assert_eq!(
        by_password.get_file(&p("/shared/report.txt")).unwrap(),
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
    let extra_id = lb.add_password(&temporary_password).unwrap();
    lb.delete_key(extra_id).unwrap();
    lb.replace_password(&old_password, &new_password).unwrap();
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
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
    assert_eq!(reopened.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
    assert_eq!(reopened.list_key_slots().len(), 1);
}

#[test]
fn key_slot_removal_compacts_old_key_material() {
    let primary_password = password("primary-password");
    let temporary_password = password("temporary-password");
    let mut lb = Lockbox::create_with_password(&primary_password).unwrap();
    let temporary_id = lb.add_password(&temporary_password).unwrap();
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.commit().unwrap();
    let before = lb.to_bytes().len();

    lb.delete_key(temporary_id).unwrap();
    let bytes = lb.to_bytes();

    assert!(bytes.len() <= before);
    assert!(matches!(
        Lockbox::open_with_password(bytes.clone(), &temporary_password),
        Err(Error::InvalidKey)
    ));
    let reopened = Lockbox::open_with_password(bytes, &primary_password).unwrap();
    assert_eq!(reopened.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
    assert_eq!(reopened.list_key_slots().len(), 1);
}

#[test]
fn path_backed_key_slot_removal_compacts_and_remains_file_backed() {
    let path = temp_path("path-backed-key-compaction");
    let primary_password = password("primary-password");
    let temporary_password = password("temporary-password");
    let mut lb =
        Lockbox::create_file(&path, LockboxProtection::Password(&primary_password)).unwrap();
    let temporary_id = lb.add_password(&temporary_password).unwrap();
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.commit().unwrap();
    let before = std::fs::metadata(&path).unwrap().len();

    lb.delete_key(temporary_id).unwrap();
    lb.add_file(&p("/docs/b.txt"), b"bravo", false).unwrap();
    lb.commit().unwrap();
    let after = std::fs::metadata(&path).unwrap().len();

    assert!(after <= before + 4 * PAGE_BYTES as u64);
    assert!(matches!(
        Lockbox::open_file(&path, LockboxUnlock::Password(&temporary_password)),
        Err(Error::InvalidKey)
    ));
    let reopened = Lockbox::open_file(&path, LockboxUnlock::Password(&primary_password)).unwrap();
    assert_eq!(reopened.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
    assert_eq!(reopened.get_file(&p("/docs/b.txt")).unwrap(), b"bravo");

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

    lb.add_file(&p("/compressible.bin"), &compressible, false)
        .unwrap();
    let vault_len = lb.to_bytes().len();

    assert!(vault_len < 4 * PAGE_BYTES);
    assert_eq!(lb.get_file(&p("/compressible.bin")).unwrap(), compressible);
}

#[test]
fn compressible_large_file_uses_fewer_pages_than_incompressible_large_file() {
    let compressible = vec![0u8; 16 * 1024 * 1024];
    let mut incompressible = vec![0u8; compressible.len()];
    fill_randomish(&mut incompressible);

    let mut compressible_box = Lockbox::create(KEY);
    compressible_box
        .add_file(&p("/compressible.bin"), &compressible, false)
        .unwrap();
    compressible_box.commit().unwrap();

    let mut incompressible_box = Lockbox::create(KEY);
    incompressible_box
        .add_file(&p("/incompressible.bin"), &incompressible, false)
        .unwrap();
    incompressible_box.commit().unwrap();

    let compressible_len = compressible_box.to_bytes().len();
    let incompressible_len = incompressible_box.to_bytes().len();
    assert!(
        compressible_len + PAGE_BYTES <= incompressible_len,
        "compressible vault should save space: {compressible_len} vs {incompressible_len}"
    );
    assert_eq!(
        compressible_box.get_file(&p("/compressible.bin")).unwrap(),
        compressible
    );
    assert_eq!(
        incompressible_box
            .get_file(&p("/incompressible.bin"))
            .unwrap(),
        incompressible
    );
}

#[test]
fn many_small_files_are_packed_into_shared_pages_after_commit() {
    let mut lb = Lockbox::create(KEY);
    let initial_len = lb.to_bytes().len();
    for i in 0..20 {
        lb.add_file(&p(format!("/packed/file-{i}.txt")), b"tiny", false)
            .unwrap();
    }
    assert_eq!(lb.to_bytes().len(), initial_len);

    lb.commit().unwrap();

    let bytes = lb.to_bytes();
    let len_after_first_commit = bytes.len();
    assert!(len_after_first_commit <= initial_len + 4 * PAGE_BYTES);

    for i in 20..30 {
        lb.add_file(&p(format!("/packed/file-{i}.txt")), b"tiny", false)
            .unwrap();
    }
    lb.commit().unwrap();
    assert!(lb.to_bytes().len() <= len_after_first_commit + 4 * PAGE_BYTES);

    let mut damaged = bytes.clone();
    damaged[0..8].fill(0);
    let report = RecoveryScanner::scan_bytes(damaged, KEY);
    assert_eq!(report.intact_file_count, 20);
}

#[test]
fn deleting_packed_file_redacts_original_page_and_preserves_other_files() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/packed/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/packed/b.txt"), b"bravo", false).unwrap();
    lb.commit().unwrap();
    let before = lb.to_bytes();
    let packed_pages_before = count_pages(&before);

    lb.delete(&p("/packed/a.txt")).unwrap();
    lb.commit().unwrap();

    let after = lb.to_bytes();
    assert_eq!(
        Lockbox::open(after.clone(), KEY)
            .unwrap()
            .get_file(&p("/packed/b.txt"))
            .unwrap(),
        b"bravo"
    );
    assert!(matches!(
        Lockbox::open(after.clone(), KEY)
            .unwrap()
            .get_file(&p("/packed/a.txt")),
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
            if let Some(page_size) = page_size_at(bytes, index) {
                index = index.saturating_add(page_size);
            } else {
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    offsets
}

fn page_size_at(bytes: &[u8], offset: usize) -> Option<usize> {
    if offset + 48 > bytes.len() {
        return None;
    }
    let header_len = u32::from_le_bytes(bytes[offset + 12..offset + 16].try_into().ok()?) as usize;
    let stored_body_len =
        u32::from_le_bytes(bytes[offset + 44..offset + 48].try_into().ok()?) as usize;
    let stored_len = header_len.checked_add(stored_body_len)?;
    Some(stored_len.checked_add(PAGE_QUANTUM_BYTES - 1)? / PAGE_QUANTUM_BYTES * PAGE_QUANTUM_BYTES)
}

#[test]
fn toc_round_trips_when_toc_payload_exceeds_minimum_page_body() {
    let mut lb = Lockbox::create(KEY);
    let payload = b"x";

    for i in 0..220 {
        let component = format!("file-{i:03}-{}.txt", "x".repeat(220));
        lb.add_file(&p(format!("/toc-overflow/{component}")), payload, false)
            .unwrap();
    }
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    let entries = reopened
        .list(ListOptions {
            recursive: true,
            ..ListOptions::new(&p("/toc-overflow"))
        })
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();

    assert_eq!(entries.len(), 220);
    assert!(reopened
        .inspector()
        .inspect_pages()
        .unwrap()
        .iter()
        .any(
            |page| page.objects.iter().any(|object| object.kind == "toc-leaf")
                && page.page_size as usize > PAGE_QUANTUM_BYTES
        ));
    assert_eq!(
        reopened
            .get_file(&p(format!(
                "/toc-overflow/file-219-{}.txt",
                "x".repeat(220)
            )))
            .unwrap(),
        payload
    );
}

#[test]
fn toc_btree_create_round_trips_multiple_leaves() {
    let mut lb = Lockbox::create(KEY);
    for i in 0..300 {
        lb.add_file(&p(format!("/toc-create/file-{i:03}.txt")), b"create", false)
            .unwrap();
    }
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened
            .list(ListOptions {
                recursive: true,
                ..ListOptions::new(&p("/toc-create"))
            })
            .unwrap()
            .count(),
        300
    );
    assert_eq!(
        reopened.get_file(&p("/toc-create/file-299.txt")).unwrap(),
        b"create"
    );
}

#[test]
fn toc_btree_append_round_trips_across_commits() {
    let mut lb = Lockbox::create(KEY);
    for i in 0..180 {
        lb.add_file(&p(format!("/toc-append/file-{i:03}.txt")), b"before", false)
            .unwrap();
    }
    lb.commit().unwrap();
    for i in 180..360 {
        lb.add_file(&p(format!("/toc-append/file-{i:03}.txt")), b"after", false)
            .unwrap();
    }
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened
            .list(ListOptions {
                recursive: true,
                ..ListOptions::new(&p("/toc-append"))
            })
            .unwrap()
            .count(),
        360
    );
    assert_eq!(
        reopened.get_file(&p("/toc-append/file-000.txt")).unwrap(),
        b"before"
    );
    assert_eq!(
        reopened.get_file(&p("/toc-append/file-359.txt")).unwrap(),
        b"after"
    );
}

#[test]
fn toc_btree_delete_round_trips_across_commits() {
    let mut lb = Lockbox::create(KEY);
    for i in 0..300 {
        lb.add_file(&p(format!("/toc-delete/file-{i:03}.txt")), b"data", false)
            .unwrap();
    }
    lb.commit().unwrap();
    for i in (0..300).step_by(3) {
        lb.delete(&p(format!("/toc-delete/file-{i:03}.txt")))
            .unwrap();
    }
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened
            .list(ListOptions {
                recursive: true,
                ..ListOptions::new(&p("/toc-delete"))
            })
            .unwrap()
            .count(),
        200
    );
    assert!(matches!(
        reopened.get_file(&p("/toc-delete/file-000.txt")),
        Err(Error::NotFound(_))
    ));
    assert_eq!(
        reopened.get_file(&p("/toc-delete/file-001.txt")).unwrap(),
        b"data"
    );
}

#[test]
fn appending_after_commit_preserves_existing_files() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.commit().unwrap();
    let len_after_first_commit = lb.to_bytes().len();

    lb.add_file(&p("/docs/b.txt"), b"bravo", false).unwrap();
    lb.commit().unwrap();

    assert!(lb.to_bytes().len() > len_after_first_commit);
    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
    assert_eq!(reopened.get_file(&p("/docs/b.txt")).unwrap(), b"bravo");
    assert_eq!(
        reopened
            .list(ListOptions::new(&p("/docs")))
            .unwrap()
            .count(),
        2
    );
}

#[test]
fn delete_removes_file_after_commit_and_reopen() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/b.txt"), b"bravo", false).unwrap();
    lb.commit().unwrap();

    lb.delete(&p("/docs/a.txt")).unwrap();
    assert!(matches!(
        lb.get_file(&p("/docs/a.txt")),
        Err(Error::NotFound(_))
    ));
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert!(matches!(
        reopened.get_file(&p("/docs/a.txt")),
        Err(Error::NotFound(_))
    ));
    assert_eq!(reopened.get_file(&p("/docs/b.txt")).unwrap(), b"bravo");
    assert_eq!(
        reopened
            .list(ListOptions::new(&p("/docs")))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn deleted_file_space_can_be_reused_by_appended_content() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/remove.bin"), &[1; 1024], false)
        .unwrap();
    lb.commit().unwrap();
    let len_after_first_commit = lb.to_bytes().len();

    lb.delete(&p("/docs/remove.bin")).unwrap();
    lb.add_file(&p("/docs/replacement.bin"), &[2; 1024], false)
        .unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert!(matches!(
        reopened.get_file(&p("/docs/remove.bin")),
        Err(Error::NotFound(_))
    ));
    assert_eq!(
        reopened.get_file(&p("/docs/replacement.bin")).unwrap(),
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
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
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

    reopened.get_file(&p("/docs/a.txt")).unwrap();
    reopened.get_file(&p("/docs/a.txt")).unwrap();
    let stats = reopened.inspector().cache_stats();
    assert!(stats.entries > 0);
    assert!(stats.hits > 0);
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
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.commit().unwrap();

    lb.get_file(&p("/docs/a.txt")).unwrap();
    assert_eq!(lb.inspector().cache_stats().entries, 0);
    assert_eq!(lb.inspector().cache_stats().used_bytes, 0);
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

    lb.add_file(&p("/bulk/data.zip"), &data, false).unwrap();

    assert_eq!(lb.inspector().cache_stats().entries, 0);
    assert_eq!(lb.inspector().cache_stats().used_bytes, 0);
    assert!(lb.inspector().storage_len().unwrap() > HEADER_LEN as u64);
    assert_eq!(lb.get_file(&p("/bulk/data.zip")).unwrap(), data);
    assert!(lb.inspector().cache_stats().entries > 0);

    lb.commit().unwrap();
    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file(&p("/bulk/data.zip")).unwrap(), data);
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
        lb.add_file(&p(format!("/bulk/small-{index:04}.zip")), &data, false)
            .unwrap();
    }

    assert!(lb.inspector().storage_len().unwrap() > HEADER_LEN as u64);
    assert_eq!(lb.inspector().cache_stats().entries, 0);
    assert_eq!(lb.get_file(&p("/bulk/small-0000.zip")).unwrap(), data);
    assert_eq!(lb.get_file(&p("/bulk/small-0399.zip")).unwrap(), data);

    lb.commit().unwrap();
    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file(&p("/bulk/small-0000.zip")).unwrap(), data);
    assert_eq!(reopened.get_file(&p("/bulk/small-0399.zip")).unwrap(), data);
}

#[test]
fn bulk_small_file_frames_keep_non_tail_pages_dense() {
    let data = vec![0xabu8; 25 * 1024];
    let mut lb = Lockbox::create_with_options(
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(128 * 1024 * 1024),
            workload_profile: WorkloadProfile::BulkImport,
        },
    );

    for index in 0..700 {
        lb.add_file(&p(format!("/bulk/dense-{index:04}.zip")), &data, false)
            .unwrap();
    }
    lb.commit().unwrap();

    let file_pages = lb
        .inspector()
        .inspect_pages()
        .unwrap()
        .into_iter()
        .filter(|page| page.objects.iter().any(|object| object.kind == "file-data"))
        .collect::<Vec<_>>();
    assert!(!file_pages.is_empty());
    assert!(
        file_pages.len() <= 3,
        "bulk small-file frames spilled into too many file pages: {}",
        file_pages.len()
    );
    for page in file_pages.iter().take(file_pages.len() - 1) {
        assert!(
            page.object_count >= 2,
            "non-tail file page at offset {} only has {} frame objects",
            page.offset,
            page.object_count
        );
    }
}

#[test]
fn extract_many_caches_decoded_compression_frames() {
    let mut lb = Lockbox::create_with_options(
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(128 * 1024 * 1024),
            workload_profile: WorkloadProfile::BulkImport,
        },
    );
    lb.add_file(&p("/cache/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/cache/b.txt"), b"bravo", false).unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open_with_options(
        lb.to_bytes(),
        KEY,
        LockboxOptions {
            cache_limit: CacheLimit::Bytes(128 * 1024 * 1024),
            workload_profile: WorkloadProfile::ExtractMany,
        },
    )
    .unwrap();

    assert_eq!(
        reopened.decoded_compression_frame_cache_entries_for_tests(),
        0
    );
    assert_eq!(reopened.get_file(&p("/cache/a.txt")).unwrap(), b"alpha");
    assert_eq!(
        reopened.decoded_compression_frame_cache_entries_for_tests(),
        1
    );
    assert_eq!(reopened.get_file(&p("/cache/b.txt")).unwrap(), b"bravo");
    assert_eq!(
        reopened.decoded_compression_frame_cache_entries_for_tests(),
        1
    );
}

#[test]
fn range_reads_are_clamped_to_file_bounds() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();

    assert_eq!(
        lb.read_file_range(&p("/docs/a.txt"), 0, 99).unwrap(),
        b"alpha"
    );
    assert_eq!(
        lb.read_file_range(&p("/docs/a.txt"), 2, 99).unwrap(),
        b"pha"
    );
    assert_eq!(lb.read_file_range(&p("/docs/a.txt"), 99, 10).unwrap(), b"");
}

#[test]
fn range_reads_only_return_requested_large_file_slice() {
    let mut lb = Lockbox::create(KEY);
    let content = vec![7u8; 8 * 1024 * 1024 + 512];
    lb.add_file(&p("/large.bin"), &content, false).unwrap();

    assert_eq!(
        lb.read_file_range(&p("/large.bin"), 8 * 1024 * 1024 - 4, 16)
            .unwrap(),
        content[8 * 1024 * 1024 - 4..8 * 1024 * 1024 + 12]
    );
}

#[test]
fn extract_to_directory_enforces_file_count_limit() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/b.txt"), b"bravo", false).unwrap();
    let dir = std::env::temp_dir().join(format!("lockbox-extract-count-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let policy = ExtractPolicy {
        max_files: 1,
        ..ExtractPolicy::default()
    };
    assert!(matches!(
        lb.extract_to_directory(&dir, &policy),
        Err(Error::SecurityLimitExceeded(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extract_to_directory_enforces_single_file_size_limit() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    let dir =
        std::env::temp_dir().join(format!("lockbox-extract-file-size-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let policy = ExtractPolicy {
        max_file_bytes: 4,
        ..ExtractPolicy::default()
    };
    assert!(matches!(
        lb.extract_to_directory(&dir, &policy),
        Err(Error::SecurityLimitExceeded(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extract_to_directory_enforces_total_size_limit() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/b.txt"), b"bravo", false).unwrap();
    let dir =
        std::env::temp_dir().join(format!("lockbox-extract-total-size-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let policy = ExtractPolicy {
        max_total_bytes: 9,
        ..ExtractPolicy::default()
    };
    assert!(matches!(
        lb.extract_to_directory(&dir, &policy),
        Err(Error::SecurityLimitExceeded(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn list_iter_and_streaming_extract_return_regular_files_when_within_limits() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/b.txt"), b"bravo", false).unwrap();

    let entries = lb
        .list(ListOptions {
            recursive: true,
            ..ListOptions::new(&p("/docs"))
        })
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries
        .iter()
        .any(|entry| entry.path == "/docs/a.txt" && entry.len == 5));

    let mut bytes = Vec::new();
    lb.extract_file_to_writer(&p("/docs/a.txt"), &mut bytes)
        .unwrap();
    assert_eq!(bytes, b"alpha");
}

#[test]
fn extract_to_directory_refuses_overwrite_by_default() {
    let dir = std::env::temp_dir().join(format!("lockbox-extract-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("docs")).unwrap();
    std::fs::write(dir.join("docs/a.txt"), "existing").unwrap();

    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();

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
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/b.txt"), b"bravo", false).unwrap();

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
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/nested/b.txt"), b"bravo", false)
        .unwrap();
    lb.add_file(&p("/other/c.txt"), b"charlie", false).unwrap();

    let docs = lb
        .list(ListOptions::new(&p("/docs")))
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].path, "/docs/a.txt");
}

#[test]
fn list_iter_streams_entries_and_supports_rust_side_filtering() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/b.pdf"), b"bravo", false).unwrap();
    lb.add_file(&p("/docs/c.pdf"), b"charlie", false).unwrap();

    let pdfs: Vec<_> = lb
        .list(ListOptions::new(&p("/docs")))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path.ends_with(".pdf"))
        .collect();

    assert_eq!(pdfs.len(), 2);
    assert!(pdfs
        .iter()
        .all(|entry| entry.kind == LockboxEntryKind::File));
}

#[test]
fn list_glob_filters_without_callback_bindings() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/b.pdf"), b"bravo", false).unwrap();
    lb.add_file(&p("/docs/nested/c.pdf"), b"charlie", false)
        .unwrap();

    let mut options = ListOptions::new(&p("/docs"));
    options.set_glob("*.pdf");
    let direct = lb
        .list(options)
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0].path, "/docs/b.pdf");

    let mut options = ListOptions::new(&p("/docs"));
    options.set_glob("**/*.pdf");
    options.recursive = true;
    let recursive = lb
        .list(options)
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(recursive.len(), 2);
}

#[test]
fn list_options_can_limit_and_filter_node_types() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_symlink(&p("/docs/current"), &p("/docs/a.txt"), false)
        .unwrap();

    let mut options = ListOptions::new(&p("/docs"));
    options.include_files = false;
    let links: Vec<_> = lb.list(options).unwrap().collect::<Result<_>>().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].kind, LockboxEntryKind::Symlink);
    assert_eq!(
        lb.get_symlink_target(&links[0].path).unwrap(),
        "/docs/a.txt"
    );

    let mut options = ListOptions::new(&p("/docs"));
    options.limit = Some(1);
    assert_eq!(lb.list(options).unwrap().count(), 1);
}

#[test]
fn symlink_support_round_trips_and_safe_extraction_skips_by_default() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file_with_permissions(&p("/docs/a.txt"), b"alpha", 0o640, false)
        .unwrap();
    lb.add_symlink(&p("/docs/current"), &p("/docs/a.txt"), false)
        .unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert!(reopened.is_symlink(&p("/docs/current")));
    assert_eq!(
        reopened.get_symlink_target(&p("/docs/current")).unwrap(),
        "/docs/a.txt"
    );
    assert_eq!(reopened.permissions(&p("/docs/a.txt")), Some(0o640));

    let files = reopened
        .list(ListOptions {
            recursive: true,
            include_symlinks: false,
            ..ListOptions::new(&p("/docs"))
        })
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].permissions, 0o640);

    let policy = ExtractPolicy {
        restore_symlinks: true,
        ..ExtractPolicy::default()
    };
    let dir = std::env::temp_dir().join(format!("lockbox-symlink-extract-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    reopened.extract_to_directory(&dir, &policy).unwrap();
    assert_eq!(std::fs::read(dir.join("docs/a.txt")).unwrap(), b"alpha");
    assert!(std::fs::symlink_metadata(dir.join("docs/current"))
        .unwrap()
        .file_type()
        .is_symlink());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn symlink_recovery_records_are_packed_into_metadata_pages() {
    let mut lb = Lockbox::create(KEY);
    for index in 0..50 {
        lb.add_symlink(
            &p(format!("/links/link-{index:02}")),
            &p(format!("/targets/target-{index:02}")),
            false,
        )
        .unwrap();
    }
    lb.commit().unwrap();

    let symlink_pages = lb
        .inspector()
        .inspect_pages()
        .unwrap()
        .into_iter()
        .filter(|page| page.objects.iter().any(|object| object.kind == "symlink"))
        .count();
    assert_eq!(symlink_pages, 1);

    let mut damaged = lb.to_bytes();
    damaged[0] ^= 0xff;
    let report = RecoveryScanner::scan_bytes(damaged, KEY);
    assert!(report.intact_files.iter().any(|entry| {
        entry.path == "/links/link-07" && entry.kind == LockboxEntryKind::Symlink
    }));
}

#[test]
fn symlink_recovery_records_spill_across_metadata_pages() {
    let mut lb = Lockbox::create(KEY);
    for index in 0..1400 {
        lb.add_symlink(
            &p(format!("/links/{index:04}/{}", "l".repeat(40))),
            &p(format!("/targets/{index:04}/{}", "t".repeat(40))),
            false,
        )
        .unwrap();
    }
    lb.commit().unwrap();

    let symlink_pages = lb
        .inspector()
        .inspect_pages()
        .unwrap()
        .into_iter()
        .filter(|page| page.objects.iter().any(|object| object.kind == "symlink"))
        .count();
    assert!(symlink_pages > 1, "expected spillover, got {symlink_pages}");

    let mut damaged = lb.to_bytes();
    damaged[0] ^= 0xff;
    let report = RecoveryScanner::scan_bytes(damaged, KEY);
    let recovered = report
        .intact_files
        .iter()
        .filter(|entry| entry.kind == LockboxEntryKind::Symlink)
        .map(|entry| entry.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(recovered.len(), 1400);
    for index in 0..1400 {
        let path = format!("/links/{index:04}/{}", "l".repeat(40));
        assert!(recovered.contains(path.as_str()));
    }
}

#[test]
fn invalid_permissions_are_rejected() {
    let mut lb = Lockbox::create(KEY);
    assert!(matches!(
        lb.add_file_with_permissions(&p("/docs/a.txt"), b"alpha", 0o1000, false),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn env_vars_round_trip_and_are_returned_as_a_map() {
    let mut lb = Lockbox::create(KEY);
    lb.set_env(&env("DATABASE_URL"), "postgres://localhost/app")
        .unwrap();
    lb.set_env(&env("FEATURE_FLAG"), "enabled").unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened.get_env(&env("DATABASE_URL")).unwrap().as_deref(),
        Some("postgres://localhost/app")
    );
    assert_eq!(
        reopened.list_env().unwrap(),
        vec![
            (env("DATABASE_URL"), EnvSensitivity::Normal),
            (env("FEATURE_FLAG"), EnvSensitivity::Normal)
        ]
    );
    let mut env = std::collections::BTreeMap::new();
    reopened
        .visit_env(|name, value| {
            let EnvValueRef::Normal(value) = value else {
                panic!("FEATURE_FLAG fixture only stores normal env values");
            };
            env.insert(
                name.to_string(),
                (value.to_string(), EnvSensitivity::Normal),
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(
        env.get("FEATURE_FLAG")
            .map(|(value, sensitivity)| (value.as_str(), *sensitivity)),
        Some(("enabled", EnvSensitivity::Normal))
    );
}

#[test]
fn env_vars_can_be_removed_and_replaced() {
    let mut lb = Lockbox::create(KEY);
    lb.set_env(&env("TOKEN"), "one").unwrap();
    lb.set_env(&env("TOKEN"), "two").unwrap();
    lb.set_env(&env("REMOVE_ME"), "gone").unwrap();
    lb.delete_env(&env("REMOVE_ME")).unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened.get_env(&env("TOKEN")).unwrap().as_deref(),
        Some("two")
    );
    assert_eq!(reopened.get_env(&env("REMOVE_ME")).unwrap(), None);
}

#[test]
fn secret_env_vars_preserve_sensitivity_until_delete() {
    let mut lb = Lockbox::create(KEY);
    let first = password("first-secret");
    let second = password("second-secret");

    lb.set_secret_env(&env("API_TOKEN"), &first).unwrap();
    lb.commit().unwrap();

    let mut reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened.env_sensitivity(&env("API_TOKEN")).unwrap(),
        Some(EnvSensitivity::Secret)
    );
    assert!(matches!(
        reopened.get_env(&env("API_TOKEN")),
        Err(Error::InvalidOperation(_))
    ));
    assert_eq!(
        reopened
            .with_secret_env(&env("API_TOKEN"), |value| value.with_str(str::to_string))
            .unwrap()
            .transpose()
            .unwrap()
            .as_deref(),
        Some("first-secret")
    );
    let mut visited = Vec::new();
    reopened
        .visit_env(|name, value| {
            let EnvValueRef::Secret(value) = value else {
                panic!("API_TOKEN fixture stores a secret env value");
            };
            value.with_str(|value| {
                visited.push((name.to_string(), value.to_string(), EnvSensitivity::Secret));
            })?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        visited,
        vec![(
            "API_TOKEN".to_string(),
            "first-secret".to_string(),
            EnvSensitivity::Secret
        )]
    );
    assert!(matches!(
        reopened.set_env(&env("API_TOKEN"), "normal"),
        Err(Error::InvalidOperation(_))
    ));

    reopened.set_secret_env(&env("API_TOKEN"), &second).unwrap();
    reopened.commit().unwrap();
    let mut reopened = Lockbox::open(reopened.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened
            .with_secret_env(&env("API_TOKEN"), |value| value.with_str(str::to_string))
            .unwrap()
            .transpose()
            .unwrap()
            .as_deref(),
        Some("second-secret")
    );

    reopened.delete_env(&env("API_TOKEN")).unwrap();
    reopened.set_env(&env("API_TOKEN"), "normal").unwrap();
    assert_eq!(
        reopened.env_sensitivity(&env("API_TOKEN")).unwrap(),
        Some(EnvSensitivity::Normal)
    );
    assert!(matches!(
        reopened.set_secret_env(&env("API_TOKEN"), &first),
        Err(Error::InvalidOperation(_))
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
    lb.set_secret_env(&env("API_TOKEN"), &secret).unwrap();
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
    assert_eq!(
        reopened
            .with_secret_env(&env("API_TOKEN"), |value| value.with_str(str::to_string))
            .unwrap()
            .transpose()
            .unwrap()
            .as_deref(),
        Some("cache-secret")
    );
    let stats_after_secret_read = reopened.inspector().cache_stats();

    assert_eq!(
        reopened.env_sensitivity(&env("API_TOKEN")).unwrap(),
        Some(EnvSensitivity::Secret)
    );
    let stats_after_sensitivity_read = reopened.inspector().cache_stats();
    assert_eq!(
        stats_after_sensitivity_read.misses,
        stats_after_secret_read.misses
    );
}

#[test]
fn many_env_vars_are_packed_into_leaf_pages() {
    let mut lb = Lockbox::create(KEY);
    for index in 0..200 {
        lb.set_env(&env(format!("VAR_{index:03}")), "value")
            .unwrap();
    }
    lb.commit().unwrap();

    let env_leaf_pages = lb
        .inspector()
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
    lb.set_env(&env("KEEP_ME"), "still-here").unwrap();
    lb.set_env(&env("REMOVE_ME"), "gone").unwrap();
    lb.commit().unwrap();
    let original_env_offset = lb
        .inspector()
        .inspect_pages()
        .unwrap()
        .into_iter()
        .find(|page| page.objects.iter().any(|object| object.kind == "env-leaf"))
        .unwrap()
        .offset;

    lb.delete_env(&env("REMOVE_ME")).unwrap();
    lb.commit().unwrap();

    let after = lb.to_bytes();
    let reopened = Lockbox::open(after.clone(), KEY).unwrap();
    assert_eq!(
        reopened.get_env(&env("KEEP_ME")).unwrap().as_deref(),
        Some("still-here")
    );
    assert_eq!(reopened.get_env(&env("REMOVE_ME")).unwrap(), None);
    assert!(lb
        .inspector()
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
    for name in ["", "1BAD", "BAD-NAME", "BAD.NAME", "BAD NAME"] {
        assert!(
            matches!(EnvName::new(name), Err(Error::InvalidPath(_))),
            "env name should be rejected: {name:?}"
        );
    }

    let mut lb = Lockbox::create(KEY);
    assert!(matches!(
        lb.set_env(&env("BAD_VALUE"), "has\0nul"),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn env_vars_are_private_and_do_not_appear_in_listings() {
    let mut lb = Lockbox::create(KEY);
    lb.set_env(&env("SECRET_TOKEN"), "super-secret").unwrap();
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.commit().unwrap();

    let bytes = lb.to_bytes();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("SECRET_TOKEN"));
    assert!(!text.contains("super-secret"));

    let reopened = Lockbox::open(bytes, KEY).unwrap();
    assert_eq!(
        reopened
            .list(ListOptions::new(&p("/docs")))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn delete_and_rename_update_the_toc() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/b.txt"), b"bravo", false).unwrap();
    lb.rename(&p("/docs/b.txt"), &p("/docs/c.txt")).unwrap();
    lb.delete(&p("/docs/a.txt")).unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert!(matches!(
        reopened.get_file(&p("/docs/a.txt")),
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        reopened.get_file(&p("/docs/b.txt")),
        Err(Error::NotFound(_))
    ));
    assert_eq!(reopened.get_file(&p("/docs/c.txt")).unwrap(), b"bravo");
}

#[test]
fn rename_moves_directory_prefixes() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/sub/b.txt"), b"bravo", false).unwrap();
    lb.add_file(&p("/other/keep.txt"), b"keep", false).unwrap();

    lb.rename(&p("/docs"), &p("/archive/docs")).unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert!(matches!(
        reopened.get_file(&p("/docs/a.txt")),
        Err(Error::NotFound(_))
    ));
    assert_eq!(
        reopened.get_file(&p("/archive/docs/a.txt")).unwrap(),
        b"alpha"
    );
    assert_eq!(
        reopened.get_file(&p("/archive/docs/sub/b.txt")).unwrap(),
        b"bravo"
    );
    assert_eq!(reopened.get_file(&p("/other/keep.txt")).unwrap(), b"keep");
}

#[test]
fn rename_moves_symlinks_inside_directory_prefixes() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/current.txt"), b"current", false)
        .unwrap();
    lb.add_symlink(&p("/docs/link.txt"), &p("/docs/current.txt"), false)
        .unwrap();

    lb.rename(&p("/docs"), &p("/archive")).unwrap();

    assert_eq!(lb.get_file(&p("/archive/current.txt")).unwrap(), b"current");
    assert_eq!(
        lb.get_symlink_target(&p("/archive/link.txt")).unwrap(),
        "/docs/current.txt"
    );
    assert!(!lb.is_symlink(&p("/docs/link.txt")));
    assert!(lb.is_symlink(&p("/archive/link.txt")));
}

#[test]
fn rename_rejects_missing_directory_prefix_and_self_nested_moves() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();

    assert!(matches!(
        lb.rename(&p("/missing"), &p("/archive")),
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        lb.rename(&p("/docs"), &p("/docs/archive")),
        Err(Error::InvalidPath(_))
    ));
}

#[test]
fn replacing_a_file_updates_content_and_keeps_old_version_out_of_toc() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"version one", false)
        .unwrap();
    lb.commit().unwrap();

    lb.add_file(&p("/docs/a.txt"), b"version two", true)
        .unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened.get_file(&p("/docs/a.txt")).unwrap(),
        b"version two"
    );
    assert_eq!(
        reopened
            .list(ListOptions::new(&p("/docs")))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn reuses_deleted_record_space_when_possible() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/large.txt"), &[7; 2 * 1024 * 1024], false)
        .unwrap();
    lb.commit().unwrap();
    let after_large = lb.to_bytes().len();

    lb.delete(&p("/docs/large.txt")).unwrap();
    lb.add_file(&p("/docs/small.txt"), b"small", false).unwrap();
    lb.commit().unwrap();
    let after_reuse = lb.to_bytes().len();

    assert!(after_reuse <= after_large + 5 * PAGE_BYTES);
    assert_eq!(lb.get_file(&p("/docs/small.txt")).unwrap(), b"small");
}

#[test]
fn reused_space_does_not_leak_old_file_path_or_content() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/secret/old-name.txt"), &[b'x'; 2048], false)
        .unwrap();
    lb.commit().unwrap();

    lb.delete(&p("/secret/old-name.txt")).unwrap();
    lb.add_file(&p("/public/new-name.txt"), b"new", false)
        .unwrap();
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

    let report = RecoveryScanner::scan_bytes(damaged, KEY);
    assert_eq!(report.intact_file_count, 3);
    assert_eq!(report.partial_files, 0);
    assert!(!report.toc_recovered);
    assert!(report.intact_files.iter().any(|e| e.path == "/docs/a.txt"));
}

#[test]
fn recovery_survives_header_toc_pointer_zeroed() {
    let mut damaged = sample_lockbox();
    damaged[16..24].fill(0);
    update_test_header_checksum(&mut damaged);

    let opened = Lockbox::open(damaged.clone(), KEY).unwrap();
    assert_eq!(opened.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");

    let report = RecoveryScanner::scan_bytes(damaged, KEY);
    assert_eq!(report.intact_file_count, 3);
    assert!(!report.toc_recovered);
}

#[test]
fn open_uses_previous_commit_when_latest_commit_root_is_corrupt() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/old.txt"), b"old", false).unwrap();
    lb.commit().unwrap();
    let previous = lb.to_bytes();

    lb.add_file(&p("/docs/new.txt"), b"new", false).unwrap();
    lb.commit().unwrap();
    let mut damaged = lb.to_bytes();
    let latest_root = u64::from_le_bytes(damaged[16..24].try_into().unwrap()) as usize;
    damaged[latest_root + 55] ^= 0xaa;

    let opened = Lockbox::open(damaged, KEY).unwrap();
    assert_eq!(opened.get_file(&p("/docs/old.txt")).unwrap(), b"old");
    assert!(matches!(
        opened.get_file(&p("/docs/new.txt")),
        Err(Error::NotFound(_))
    ));
    assert_eq!(
        Lockbox::open(previous, KEY)
            .unwrap()
            .get_file(&p("/docs/old.txt"))
            .unwrap(),
        b"old"
    );
}

#[test]
fn stale_header_after_interrupted_commit_opens_last_published_state() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/old.txt"), b"old", false).unwrap();
    lb.commit().unwrap();
    let previous = lb.to_bytes();

    lb.add_file(&p("/docs/new.txt"), b"new", false).unwrap();
    lb.commit().unwrap();
    let mut interrupted = lb.to_bytes();
    interrupted[0..HEADER_LEN].copy_from_slice(&previous[0..HEADER_LEN]);

    let opened = Lockbox::open(interrupted, KEY).unwrap();
    assert_eq!(opened.get_file(&p("/docs/old.txt")).unwrap(), b"old");
    assert!(matches!(
        opened.get_file(&p("/docs/new.txt")),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn recovery_survives_corrupt_toc_record() {
    let bytes = sample_lockbox();
    let lb = Lockbox::open(bytes.clone(), KEY).unwrap();
    let mut damaged = bytes;

    let header_toc_root_offset = u64::from_le_bytes(damaged[16..24].try_into().unwrap()) as usize;
    damaged[header_toc_root_offset + 55] ^= 0x55;

    assert!(Lockbox::open(damaged.clone(), KEY).is_err());

    let report = RecoveryScanner::scan_bytes(damaged, KEY);
    assert_eq!(report.intact_file_count, 3);
    assert_eq!(report.partial_files, 0);
    assert!(!report.toc_recovered);
    assert_eq!(lb.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
}

#[test]
fn recovery_ignores_deleted_files_when_rebuilding_without_toc() {
    let mut lb = Lockbox::create(KEY);
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/delete-me.txt"), b"delete", false)
        .unwrap();
    lb.delete(&p("/docs/delete-me.txt")).unwrap();
    lb.commit().unwrap();

    let mut damaged = lb.to_bytes();
    let header_toc_root_offset = u64::from_le_bytes(damaged[16..24].try_into().unwrap()) as usize;
    damaged[header_toc_root_offset + 55] ^= 0x55;

    let report = RecoveryScanner::scan_bytes(damaged, KEY);
    assert_eq!(report.intact_file_count, 1);
    assert!(report
        .intact_files
        .iter()
        .all(|entry| entry.path != "/docs/delete-me.txt"));
}

#[test]
fn recovery_reports_partial_when_file_record_is_corrupt_but_toc_survives() {
    let bytes = sample_lockbox();
    let lb = Lockbox::open(bytes.clone(), KEY).unwrap();
    let mut damaged = bytes;

    let entry = lb.stat(&p("/docs/a.txt")).unwrap();
    assert_eq!(entry.len, 5);
    let first_record_offset = 64usize;
    damaged[first_record_offset + 55] ^= 0xaa;

    let report = RecoveryScanner::scan_bytes(damaged, KEY);
    assert!(report.toc_recovered);
    assert_eq!(report.intact_file_count, 2);
    assert_eq!(report.partial_files, 1);
    assert!(report.intact_files.iter().any(|e| e.path == "/docs/a.txt"));
}

#[test]
fn recovery_reports_corrupt_records_for_damaged_frame_header() {
    let mut damaged = sample_lockbox();
    damaged[64 + 44] ^= 0x11;

    let report = RecoveryScanner::scan_bytes(damaged, KEY);
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

    let report = RecoveryScanner::scan_bytes(damaged, KEY);
    assert_eq!(report.intact_file_count, 3);
    assert!(!report.toc_recovered);
}

#[test]
fn salvage_writes_intact_files_to_a_clean_lockbox() {
    let bytes = sample_lockbox();
    let mut damaged = bytes;
    damaged[0] ^= 0xff;

    let salvaged = RecoveryScanner::salvage_bytes(damaged, KEY).unwrap();
    assert_eq!(salvaged.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
    assert_eq!(salvaged.get_file(&p("/docs/b.txt")).unwrap(), b"bravo");
    assert_eq!(salvaged.get_file(&p("/photos/c.jpg")).unwrap(), b"image");
}

#[test]
fn salvage_omits_corrupt_file_records() {
    let mut damaged = sample_lockbox();
    damaged[64 + 55] ^= 0xaa;

    let salvaged = RecoveryScanner::salvage_bytes(damaged, KEY).unwrap();
    assert!(matches!(
        salvaged.get_file(&p("/docs/a.txt")),
        Err(Error::NotFound(_))
    ));
    assert_eq!(salvaged.get_file(&p("/docs/b.txt")).unwrap(), b"bravo");
    assert_eq!(salvaged.get_file(&p("/photos/c.jpg")).unwrap(), b"image");
}

#[test]
fn wrong_key_cannot_open_or_recover_private_metadata() {
    let bytes = sample_lockbox();
    assert!(Lockbox::open(bytes.clone(), b"wrong key").is_err());

    let report = RecoveryScanner::scan_bytes(bytes, b"wrong key");
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
fn many_files_round_trip_and_recover_after_toc_loss() {
    let mut lb = Lockbox::create(KEY);
    for i in 0..100 {
        let path = format!("/many/file-{i:03}.txt");
        let content = format!("content-{i:03}");
        lb.add_file(&p(&path), content.as_bytes(), false).unwrap();
    }
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(
        reopened
            .list(ListOptions::new(&p("/many")))
            .unwrap()
            .count(),
        100
    );
    assert_eq!(
        reopened.get_file(&p("/many/file-042.txt")).unwrap(),
        b"content-042"
    );

    let mut damaged = reopened.to_bytes();
    let header_toc_root_offset = u64::from_le_bytes(damaged[16..24].try_into().unwrap()) as usize;
    damaged[header_toc_root_offset + 55] ^= 0x55;
    let report = RecoveryScanner::scan_bytes(damaged, KEY);
    assert_eq!(report.intact_file_count, 100);
}

#[test]
fn large_file_recovery_reassembles_segments_after_toc_loss() {
    let mut payload = vec![0u8; 9 * 1024 * 1024];
    fill_randomish(&mut payload);
    let mut lb = Lockbox::create(KEY);
    lb.add_file_from_reader(&p("/large/recover.bin"), Cursor::new(&payload), false)
        .unwrap();
    lb.commit().unwrap();

    let mut damaged = lb.to_bytes();
    let header_toc_root_offset = u64::from_le_bytes(damaged[16..24].try_into().unwrap()) as usize;
    damaged[header_toc_root_offset + 55] ^= 0x55;

    let report = RecoveryScanner::scan_bytes(damaged.clone(), KEY);
    assert_eq!(report.intact_file_count, 1);
    assert_eq!(report.partial_files, 0);

    let salvaged = RecoveryScanner::salvage_bytes(damaged, KEY).unwrap();
    assert_eq!(
        salvaged.get_file(&p("/large/recover.bin")).unwrap(),
        payload
    );
}

#[test]
fn recovery_report_default_summarizes_intact_files_without_listing_them() {
    let report = RecoveryScanner::scan_bytes(sample_lockbox(), KEY);
    let rendered = report.render(&RecoveryReportOptions::default());

    assert!(rendered.contains("Intact files: 3"));
    assert!(!rendered.contains("/docs/a.txt"));
    assert!(!rendered.contains("Intact:\n  /docs/a.txt"));
}

#[test]
fn recovery_report_verbose_lists_intact_files_with_optional_limit() {
    let report = RecoveryScanner::scan_bytes(sample_lockbox(), KEY);
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
    lb.add_file_from_reader(&p("/large/source.bin"), Cursor::new(&payload), false)
        .unwrap();
    lb.commit().unwrap();
    let before = lb.to_bytes().len();

    lb.rename(&p("/large/source.bin"), &p("/archive/renamed.bin"))
        .unwrap();
    lb.commit().unwrap();
    let after = lb.to_bytes().len();

    assert!(
        after <= before + 4 * PAGE_BYTES,
        "rename rewrote too much data: before={before}, after={after}"
    );
    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert!(matches!(
        reopened.get_file(&p("/large/source.bin")),
        Err(Error::NotFound(_))
    ));
    assert_eq!(
        reopened.get_file(&p("/archive/renamed.bin")).unwrap(),
        payload
    );

    let report = RecoveryScanner::scan_bytes(lb.to_bytes(), KEY);
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
    lb.add_file_from_reader(&p("/large/blob.bin"), Cursor::new(&payload), false)
        .unwrap();
    lb.add_file(&p("/small.txt"), b"small", false).unwrap();
    lb.commit().unwrap();

    lb.delete(&p("/small.txt")).unwrap();
    lb.compact().unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open(lb.to_bytes(), KEY).unwrap();
    assert_eq!(reopened.get_file(&p("/large/blob.bin")).unwrap(), payload);
    assert!(matches!(
        reopened.get_file(&p("/small.txt")),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn path_backed_compact_logically_rewrites_live_state() {
    let path = temp_path("path-backed-logical-compact");
    let payload = vec![0x51u8; PAGE_BYTES + 123];
    let _ = std::fs::remove_file(&path);

    let mut lb = Lockbox::create_path(&path, KEY).unwrap();
    lb.add_file_from_reader(&p("/large/blob.bin"), Cursor::new(&payload), false)
        .unwrap();
    lb.add_file(&p("/empty.bin"), b"", false).unwrap();
    lb.add_file(&p("/stale.txt"), b"remove me", false).unwrap();
    lb.add_symlink(&p("/links/current"), &p("/large/blob.bin"), false)
        .unwrap();
    lb.set_env(&env("TOKEN"), "old").unwrap();
    lb.commit().unwrap();

    lb.delete(&p("/stale.txt")).unwrap();
    lb.set_env(&env("TOKEN"), "new").unwrap();
    lb.compact().unwrap();

    let reopened = Lockbox::open_path(&path, KEY).unwrap();
    assert_eq!(reopened.get_file(&p("/large/blob.bin")).unwrap(), payload);
    assert_eq!(reopened.get_file(&p("/empty.bin")).unwrap(), b"");
    assert_eq!(
        reopened.get_symlink_target(&p("/links/current")).unwrap(),
        "/large/blob.bin"
    );
    assert_eq!(
        reopened.get_env(&env("TOKEN")).unwrap().as_deref(),
        Some("new")
    );
    assert!(matches!(
        reopened.get_file(&p("/stale.txt")),
        Err(Error::NotFound(_))
    ));

    let _ = std::fs::remove_file(path);
}

fn sample_lockbox() -> Vec<u8> {
    let mut lb = Lockbox::create(KEY);
    lb.add_file_from_reader(&p("/docs/a.txt"), Cursor::new(b"alpha"), false)
        .unwrap();
    lb.add_file_from_reader(&p("/docs/b.txt"), Cursor::new(b"bravo"), false)
        .unwrap();
    lb.add_file_from_reader(&p("/photos/c.jpg"), Cursor::new(b"image"), false)
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
