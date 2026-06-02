use lockbox_core::{
    EnvName, EnvValueRef, ExtractPolicy, ListOptions, Lockbox, LockboxId, LockboxKeySlotAlgorithm,
    LockboxKeySlotProtection, LockboxPath, LockboxProtection, LockboxUnlock, RecipientKeyPair,
    RecipientPublicKey, RecipientWrappedKey, RecoveryReportOptions, RecoveryScanner, SecretString,
    SecretVec, WorkloadProfile,
};
use std::io::Cursor;
use std::path::{Path, PathBuf};

const KEY: &[u8] = b"public api suite key";

fn p(path: impl AsRef<str>) -> LockboxPath {
    LockboxPath::new(path).unwrap()
}

fn env(name: impl AsRef<str>) -> EnvName {
    EnvName::new(name).unwrap()
}

#[test]
fn public_api_files_listing_env_symlink_and_rename_flow() {
    let root = unique_dir("files");
    let lockbox_path = root.join("files.lbox");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let mut lb = Lockbox::create_file(
        &lockbox_path,
        LockboxProtection::ContentKey(SecretVec::try_from_slice(KEY).unwrap()),
    )
    .unwrap();
    lb.add_file_with_permissions(&p("/app/config.json"), br#"{"mode":"test"}"#, 0o640, false)
        .unwrap();
    lb.add_file_from_reader(
        &p("/app/logs/today.txt"),
        Cursor::new(b"hello from a reader"),
        false,
    )
    .unwrap();
    lb.add_symlink(&p("/app/latest.log"), &p("/app/logs/today.txt"), false)
        .unwrap();
    lb.set_env(&env("DATABASE_URL"), "postgres://localhost/app")
        .unwrap();
    lb.set_env(&env("API_TOKEN"), "secret-token").unwrap();
    lb.rename(&p("/app"), &p("/srv/app")).unwrap();
    lb.commit().unwrap();

    let reopened = Lockbox::open_file(
        &lockbox_path,
        LockboxUnlock::ContentKey(SecretVec::try_from_slice(KEY).unwrap()),
    )
    .unwrap();
    assert_eq!(
        reopened.get_file(&p("/srv/app/config.json")).unwrap(),
        br#"{"mode":"test"}"#
    );
    assert_eq!(
        reopened
            .read_file_range(&p("/srv/app/logs/today.txt"), 6, 4)
            .unwrap(),
        b"from"
    );
    assert_eq!(
        reopened.permissions(&p("/srv/app/config.json")),
        Some(0o640)
    );
    assert!(reopened.is_symlink(&p("/srv/app/latest.log")));
    assert_eq!(
        reopened
            .get_symlink_target(&p("/srv/app/latest.log"))
            .unwrap(),
        "/app/logs/today.txt"
    );

    let entries = reopened
        .list(ListOptions {
            path: p("/srv"),
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

    let mut env = std::collections::BTreeMap::new();
    reopened
        .visit_env(|name, value| {
            let EnvValueRef::Normal(value) = value else {
                panic!("fixture stores normal env values");
            };
            env.insert(
                name.to_string(),
                (value.to_string(), lockbox_core::EnvSensitivity::Normal),
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(
        env.get("DATABASE_URL")
            .map(|(value, sensitivity)| (value.as_str(), *sensitivity)),
        Some((
            "postgres://localhost/app",
            lockbox_core::EnvSensitivity::Normal
        ))
    );
    assert_eq!(
        env.get("API_TOKEN")
            .map(|(value, sensitivity)| (value.as_str(), *sensitivity)),
        Some(("secret-token", lockbox_core::EnvSensitivity::Normal))
    );
    assert!(reopened
        .list(ListOptions::new(&p("/srv")))
        .unwrap()
        .all(|entry| {
            let entry = entry.unwrap();
            !entry.path.contains("DATABASE_URL") && !entry.path.contains("API_TOKEN")
        }));

    let all_entries = reopened
        .list(ListOptions {
            path: p("/srv"),
            glob: None,
            recursive: true,
            include_files: true,
            include_symlinks: true,
            limit: None,
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(all_entries
        .iter()
        .any(|entry| { entry.path == "/srv/app/config.json" && entry.permissions == 0o640 }));
    assert!(all_entries
        .iter()
        .any(|entry| { entry.path == "/srv/app/latest.log" }));

    let mut streamed = Vec::new();
    reopened
        .extract_file_to_writer(&p("/srv/app/config.json"), &mut streamed)
        .unwrap();
    assert_eq!(streamed, br#"{"mode":"test"}"#);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn public_api_password_and_recipient_key_management_flow() {
    let root = unique_dir("keys");
    let lockbox_path = root.join("shared.lbox");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let recipient = RecipientKeyPair::generate().unwrap();
    let old_password = password("old-password");
    let new_password = password("new-password");
    let mut lb =
        Lockbox::create_file(&lockbox_path, LockboxProtection::Password(&old_password)).unwrap();
    let password_slot = lb.list_key_slots()[0].id;
    let recipient_slot = lb.add_recipient(&recipient.public_key()).unwrap();
    let slots = lb.list_key_slots();
    assert!(slots.iter().any(|slot| {
        slot.id == password_slot
            && slot.protection == LockboxKeySlotProtection::Password
            && slot.algorithm == LockboxKeySlotAlgorithm::Argon2idChaCha20Poly1305
    }));
    assert!(slots.iter().any(|slot| {
        slot.id == recipient_slot
            && slot.protection == LockboxKeySlotProtection::Recipient
            && slot.algorithm == LockboxKeySlotAlgorithm::MlKem1024ChaCha20Poly1305
    }));

    lb.add_file(&p("/secret.txt"), b"shared", false).unwrap();
    lb.commit().unwrap();
    drop(lb);

    assert_eq!(
        Lockbox::open_file(&lockbox_path, LockboxUnlock::Password(&old_password))
            .unwrap()
            .get_file(&p("/secret.txt"))
            .unwrap(),
        b"shared"
    );
    assert_eq!(
        Lockbox::open_file(&lockbox_path, LockboxUnlock::RecipientKeyPair(recipient))
            .unwrap()
            .get_file(&p("/secret.txt"))
            .unwrap(),
        b"shared"
    );

    let mut reopened =
        Lockbox::open_file(&lockbox_path, LockboxUnlock::Password(&old_password)).unwrap();
    let new_slot = reopened
        .replace_password(&old_password, &new_password)
        .unwrap();
    reopened.commit().unwrap();

    let slots = reopened.list_key_slots();
    assert!(slots
        .iter()
        .any(|slot| slot.id == new_slot && slot.protection == LockboxKeySlotProtection::Password));
    assert!(slots.iter().all(|slot| slot.id != password_slot));
    assert!(Lockbox::open_file(&lockbox_path, LockboxUnlock::Password(&new_password)).is_ok());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn public_api_recovery_scanner_reports_and_salvages_intact_files() {
    let root = unique_dir("recovery");
    let lockbox_path = root.join("recovery.lbox");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let mut lb = Lockbox::create_file(
        &lockbox_path,
        LockboxProtection::ContentKey(SecretVec::try_from_slice(KEY).unwrap()),
    )
    .unwrap();
    lb.add_file(&p("/docs/a.txt"), b"alpha", false).unwrap();
    lb.add_file(&p("/docs/b.txt"), b"bravo", false).unwrap();
    lb.add_file(&p("/photos/c.jpg"), b"image", false).unwrap();
    lb.commit().unwrap();

    let mut damaged = std::fs::read(&lockbox_path).unwrap();
    damaged[0] ^= 0xff;

    let report = RecoveryScanner::scan_bytes(damaged.clone(), KEY);
    assert_eq!(report.intact_file_count, 3);
    assert!(report
        .render(&RecoveryReportOptions::default())
        .contains("Intact files"));

    let salvaged = RecoveryScanner::salvage_bytes(damaged, KEY).unwrap();
    assert_eq!(salvaged.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
    assert_eq!(salvaged.get_file(&p("/docs/b.txt")).unwrap(), b"bravo");
    assert_eq!(salvaged.get_file(&p("/photos/c.jpg")).unwrap(), b"image");

    let _ = std::fs::remove_dir_all(root);
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

    let keypair = RecipientKeyPair::generate().unwrap();
    let from_seed = RecipientKeyPair::from_private_seed(keypair.private_seed().unwrap()).unwrap();
    let recipient = keypair.public_key();
    let recipient = RecipientPublicKey::from_bytes(&recipient.to_bytes()).unwrap();
    let wrapped = recipient.encrypt(b"content-key").unwrap();
    let wrapped = RecipientWrappedKey::from_parts(
        wrapped.ciphertext_bytes().to_vec(),
        wrapped.encrypted_key().to_vec(),
    )
    .unwrap();
    assert_eq!(from_seed.decrypt(&wrapped).unwrap(), b"content-key");
    assert_eq!(
        from_seed
            .encrypt(b"another-key")
            .unwrap()
            .encrypted_key()
            .len(),
        27
    );
}

#[test]
fn public_api_path_inspector_and_file_helpers_flow() {
    let root = unique_dir("helpers");
    let lockbox_path = root.join("helpers.lbox");
    let source_path = root.join("source.txt");
    let extract_path = root.join("extracted.txt");
    let extract_dir = root.join("extract-dir");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&source_path, b"from disk").unwrap();

    let mut lb = Lockbox::create_file(
        &lockbox_path,
        LockboxProtection::ContentKey(SecretVec::try_from_slice(KEY).unwrap()),
    )
    .unwrap();
    assert_eq!(lb.workload_profile(), WorkloadProfile::Interactive);
    lb.set_workload_profile(WorkloadProfile::ReadMostly);
    assert_eq!(lb.workload_profile(), WorkloadProfile::ReadMostly);

    lb.add_file_from_path(&source_path, &p("/docs/source.txt"), false)
        .unwrap();
    lb.add_file_from_reader(&p("/docs/reader.txt"), Cursor::new(b"from reader"), false)
        .unwrap();
    lb.set_env(&env("TEMP"), "1").unwrap();
    lb.delete_env(&env("TEMP")).unwrap();
    lb.commit().unwrap();

    let entries = lb.list(ListOptions::new(&p("/docs"))).unwrap();
    assert_eq!(entries.count(), 2);
    let mut out = Vec::new();
    lb.extract_file_to_writer(&p("/docs/source.txt"), &mut out)
        .unwrap();
    assert_eq!(out, b"from disk");
    out.clear();
    lb.extract_file_to_writer(&p("/docs/reader.txt"), &mut out)
        .unwrap();
    assert_eq!(out, b"from reader");
    lb.extract_file_to(&p("/docs/source.txt"), &extract_path, false)
        .unwrap();
    assert_eq!(std::fs::read(&extract_path).unwrap(), b"from disk");
    assert!(matches!(
        lb.extract_file_to(&p("/docs/source.txt"), &extract_path, false),
        Err(lockbox_core::Error::AlreadyExists(_))
    ));
    lb.extract_file_to(&p("/docs/reader.txt"), &extract_path, true)
        .unwrap();
    assert_eq!(std::fs::read(&extract_path).unwrap(), b"from reader");
    let missing_extract_path = root.join("missing-extract.txt");
    assert!(matches!(
        lb.extract_file_to(&p("/docs/source.txt"), &missing_extract_path, true),
        Err(lockbox_core::Error::NotFound(_))
    ));
    lb.extract_to_directory(&extract_dir, &ExtractPolicy::default())
        .unwrap();
    assert_eq!(
        std::fs::read(extract_dir.join("docs/source.txt")).unwrap(),
        b"from disk"
    );

    let inspector = lb.inspector();
    assert!(inspector.storage_len().unwrap() > 0);
    assert!(!inspector.inspect_pages().unwrap().is_empty());
    let _ = inspector.cache_stats();
    assert_eq!(
        RecoveryScanner::scan_path(&lockbox_path, KEY).intact_file_count,
        2
    );

    let reopened = Lockbox::open_file(
        &lockbox_path,
        LockboxUnlock::ContentKey(SecretVec::try_from_slice(KEY).unwrap()),
    )
    .unwrap();
    assert_eq!(
        reopened.get_file(&p("/docs/source.txt")).unwrap(),
        b"from disk"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn public_api_password_recipient_open_file_flow() {
    let root = unique_dir("unlock");
    let password_path = root.join("password.lbox");
    let recipient_path = root.join("recipient.lbox");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let password = password("shared-password");
    let mut by_password =
        Lockbox::create_file(&password_path, LockboxProtection::Password(&password)).unwrap();
    by_password
        .add_file(&p("/secret.txt"), b"password", false)
        .unwrap();
    by_password.commit().unwrap();
    assert_eq!(
        Lockbox::open_file(&password_path, LockboxUnlock::Password(&password))
            .unwrap()
            .get_file(&p("/secret.txt"))
            .unwrap(),
        b"password"
    );

    let recipient = RecipientKeyPair::generate().unwrap();
    let mut by_recipient = Lockbox::create_file(
        &recipient_path,
        LockboxProtection::RecipientPublicKey {
            name: Some("recipient".to_string()),
            recipient: recipient.public_key(),
        },
    )
    .unwrap();
    by_recipient
        .add_file(&p("/secret.txt"), b"recipient", false)
        .unwrap();
    by_recipient.commit().unwrap();
    assert_eq!(
        Lockbox::open_file(&recipient_path, LockboxUnlock::RecipientKeyPair(recipient))
            .unwrap()
            .get_file(&p("/secret.txt"))
            .unwrap(),
        b"recipient"
    );

    let _ = std::fs::remove_dir_all(root);
}

fn password(value: &str) -> SecretString {
    SecretString::try_from_bytes(value.as_bytes().to_vec()).unwrap()
}

fn unique_dir(label: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
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
