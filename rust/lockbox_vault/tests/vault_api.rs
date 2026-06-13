use lockbox_core::vault_bridge::VaultUnlock;
use lockbox_core::{
    Error, Lockbox, LockboxPath, LockboxProtection, LockboxUnlock, OwnerSigningKeyPair,
    RecipientKeyPair, Result, SecretVec,
};
use lockbox_vault::{
    export_private_key, import_private_key_file, ContentKeyStore, IdentityGenerationStatus,
    KeyFormat, SecretString, Vault, VaultDirectory, CURRENT_VAULT_STRUCTURE_VERSION,
};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn p(path: impl AsRef<str>) -> LockboxPath {
    LockboxPath::new(path).unwrap()
}

#[derive(Default)]
struct MemoryStore {
    keys: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl ContentKeyStore for MemoryStore {
    fn get_content_key(&self, lockbox_id: lockbox_core::LockboxId) -> Result<Option<SecretVec>> {
        self.keys
            .borrow()
            .get(&lockbox_id.to_string())
            .map(|key| SecretVec::try_from_slice(key))
            .transpose()
            .map_err(Into::into)
    }

    fn put_content_key(&self, lockbox_id: lockbox_core::LockboxId, key: SecretVec) -> Result<()> {
        let key = key.with_bytes(|key| key.to_vec())?;
        self.keys.borrow_mut().insert(lockbox_id.to_string(), key);
        Ok(())
    }

    fn forget_content_key(&self, lockbox_id: lockbox_core::LockboxId) -> Result<()> {
        self.keys.borrow_mut().remove(&lockbox_id.to_string());
        Ok(())
    }

    fn forget_all_content_keys(&self) -> Result<()> {
        self.keys.borrow_mut().clear();
        Ok(())
    }
}

#[derive(Default)]
struct SecureCloneStore {
    keys: RefCell<BTreeMap<String, SecretVec>>,
}

impl ContentKeyStore for SecureCloneStore {
    fn get_content_key(&self, lockbox_id: lockbox_core::LockboxId) -> Result<Option<SecretVec>> {
        self.keys
            .borrow()
            .get(&lockbox_id.to_string())
            .map(SecretVec::try_clone)
            .transpose()
            .map_err(Into::into)
    }

    fn put_content_key(&self, lockbox_id: lockbox_core::LockboxId, key: SecretVec) -> Result<()> {
        let key = key.try_clone()?;
        self.keys.borrow_mut().insert(lockbox_id.to_string(), key);
        Ok(())
    }

    fn forget_content_key(&self, lockbox_id: lockbox_core::LockboxId) -> Result<()> {
        self.keys.borrow_mut().remove(&lockbox_id.to_string());
        Ok(())
    }

    fn forget_all_content_keys(&self) -> Result<()> {
        self.keys.borrow_mut().clear();
        Ok(())
    }
}

#[test]
fn vault_create_open_and_lock_with_content_key() {
    let path = unique_path("raw");
    let vault = Vault::new(MemoryStore::default());
    let key = SecretVec::try_from_slice(b"0123456789abcdef0123456789abcdef").unwrap();

    let mut lockbox = vault
        .create_lockbox(&path, LockboxProtection::ContentKey(key))
        .unwrap();
    lockbox
        .add_file(&p("/docs/a.txt"), b"alpha", false)
        .unwrap();
    lockbox.commit().unwrap();

    let opened = vault.open_lockbox(&path).unwrap();
    assert_eq!(opened.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");

    vault.lock_lockbox(&path).unwrap();
    assert!(matches!(
        vault.open_lockbox(&path),
        Err(Error::VaultUnavailable(_))
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn vault_password_create_and_unlock_cache_keys_outside_secure_read_access() {
    let path = unique_path("password-secure-cache");
    let vault = Vault::new(SecureCloneStore::default());
    let password = SecretString::try_from_slice(b"password").unwrap();

    let mut lockbox = vault
        .create_lockbox_with_password(&path, &password)
        .unwrap();
    lockbox
        .add_file(&p("/docs/a.txt"), b"alpha", false)
        .unwrap();
    lockbox.commit().unwrap();

    let cached = vault.open_lockbox(&path).unwrap();
    assert_eq!(cached.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");

    vault.lock_lockbox(&path).unwrap();
    assert!(matches!(
        vault.open_lockbox(&path),
        Err(Error::VaultUnavailable(_))
    ));

    let unlocked = vault
        .unlock_lockbox_with_password(&path, &password)
        .unwrap();
    assert_eq!(unlocked.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");

    let recached = vault.open_lockbox(&path).unwrap();
    assert_eq!(recached.get_file(&p("/docs/a.txt")).unwrap(), b"alpha");
}

#[test]
fn vault_open_populates_cache_for_password_lockbox() {
    let path = unique_path("password");
    let vault = Vault::new(MemoryStore::default());
    let password = SecretString::try_from_bytes(b"shared password".to_vec()).unwrap();

    let mut lockbox = vault
        .create_lockbox(&path, LockboxProtection::Password(&password))
        .unwrap();
    lockbox
        .add_file(&p("/secret.txt"), b"bravo", false)
        .unwrap();
    lockbox.commit().unwrap();
    vault.lock_lockbox(&path).unwrap();

    assert!(matches!(
        vault.open_lockbox(&path),
        Err(Error::VaultUnavailable(_))
    ));

    vault
        .unlock_lockbox(&path, LockboxUnlock::Password(&password))
        .unwrap();
    let opened = vault.open_lockbox(&path).unwrap();
    assert_eq!(opened.get_file(&p("/secret.txt")).unwrap(), b"bravo");

    let _ = fs::remove_file(path);
}

#[test]
fn vault_directory_stores_local_keys_contacts_and_key_directory_backups() {
    let root = unique_dir("directory");
    let vault_password = SecretString::try_from_bytes(b"vault-password".to_vec()).unwrap();
    let vault = VaultDirectory::unlock_or_create(&root, &vault_password).unwrap();
    assert_eq!(
        vault.structure_version().unwrap(),
        CURRENT_VAULT_STRUCTURE_VERSION
    );
    let keypair = RecipientKeyPair::generate().unwrap();
    vault.store_private_key("default", &keypair).unwrap();
    let encrypted = fs::read(root.join("local-vault.lbox")).unwrap();
    assert!(!String::from_utf8_lossy(&encrypted).contains("default.key"));
    assert!(!String::from_utf8_lossy(&encrypted).contains("private-key-password"));
    let loaded = vault.load_private_key("default").unwrap();
    assert_eq!(
        loaded.private_key_record().unwrap(),
        keypair.private_key_record().unwrap()
    );

    vault.store_contact("alice", &keypair.public_key()).unwrap();
    let contacts = vault.list_contacts().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].name, "alice");

    assert_eq!(vault.seed_default_form_definitions().unwrap(), 7);
    assert_eq!(vault.seed_default_form_definitions().unwrap(), 0);
    let form_aliases = vault
        .list_form_definitions()
        .unwrap()
        .into_iter()
        .map(|definition| definition.alias)
        .collect::<Vec<_>>();
    for alias in [
        "bank-account",
        "identity",
        "login",
        "payment-card",
        "secure-note",
        "server",
        "wifi",
    ] {
        assert!(form_aliases.contains(&alias.to_string()), "{alias}");
    }

    let password = SecretString::try_from_bytes(b"pw".to_vec()).unwrap();
    let lockbox_path = root.join("backup-source.lbox");
    let mut lockbox =
        Lockbox::create_file(&lockbox_path, LockboxProtection::Password(&password)).unwrap();
    lockbox.add_file(&p("/a.txt"), b"alpha", false).unwrap();
    lockbox.commit().unwrap();
    let backup = VaultUnlock::export_key_directory_backup(&lockbox).unwrap();
    vault
        .store_key_directory_backup(lockbox.lockbox_id(), &backup)
        .unwrap();
    vault
        .store_key_directory_backup(lockbox.lockbox_id(), &backup)
        .unwrap();
    assert_eq!(
        vault
            .load_key_directory_backup(lockbox.lockbox_id())
            .unwrap(),
        backup
    );
    assert_eq!(vault.key_directory_backup_count().unwrap(), 1);

    vault
        .remember_known_lockbox(lockbox.lockbox_id(), &lockbox_path)
        .unwrap();
    let known = vault.list_known_lockboxes().unwrap();
    assert_eq!(known.len(), 1);
    assert_eq!(known[0].lockbox_id, lockbox.lockbox_id());
    assert_eq!(known[0].path, lockbox_path.to_string_lossy());
    vault.forget_known_lockbox(&lockbox_path).unwrap();
    assert!(vault.list_known_lockboxes().unwrap().is_empty());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn vault_directory_rejects_unversioned_existing_vaults() {
    let root = unique_dir("legacy-vault-version");
    fs::create_dir_all(&root).unwrap();
    let vault_path = root.join("local-vault.lbox");
    let vault_password = SecretString::try_from_bytes(b"vault-password".to_vec()).unwrap();

    Lockbox::create_file(&vault_path, LockboxProtection::Password(&vault_password)).unwrap();

    assert!(matches!(
        VaultDirectory::unlock_or_create(&root, &vault_password),
        Err(Error::Configuration(message))
            if message.contains("structure version is missing")
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn vault_directory_rejects_older_structure_versions() {
    let root = unique_dir("explicit-legacy-vault-version");
    let vault_password = SecretString::try_from_bytes(b"vault-password".to_vec()).unwrap();
    VaultDirectory::unlock_or_create(&root, &vault_password).unwrap();

    let vault_path = root.join("local-vault.lbox");
    let mut lockbox =
        Lockbox::open_file(&vault_path, LockboxUnlock::Password(&vault_password)).unwrap();
    lockbox
        .add_file(&p("/vault/structure-version"), b"0\n", true)
        .unwrap();
    lockbox.commit().unwrap();

    assert!(matches!(
        VaultDirectory::unlock_or_create(&root, &vault_password),
        Err(Error::Configuration(message)) if message.contains("cannot be migrated")
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn vault_directory_rejects_newer_structure_versions() {
    let root = unique_dir("future-vault-version");
    let vault_password = SecretString::try_from_bytes(b"vault-password".to_vec()).unwrap();
    VaultDirectory::unlock_or_create(&root, &vault_password).unwrap();

    let vault_path = root.join("local-vault.lbox");
    let mut lockbox =
        Lockbox::open_file(&vault_path, LockboxUnlock::Password(&vault_password)).unwrap();
    lockbox
        .add_file(&p("/vault/structure-version"), b"999\n", true)
        .unwrap();
    lockbox.commit().unwrap();

    assert!(matches!(
        VaultDirectory::unlock_or_create(&root, &vault_password),
        Err(Error::Configuration(message))
            if message.contains("newer than this reVault build supports")
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn vault_unlock_uses_key_directory_backup_when_embedded_directory_is_corrupt() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let path = unique_path("backup-fallback");
    let vault_root = unique_dir("backup-fallback-vault");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir_all(&vault_root);

    let password = SecretString::try_from_bytes(b"shared password".to_vec()).unwrap();
    let mut lockbox = Lockbox::create_file(&path, LockboxProtection::Password(&password))
        .expect("create password lockbox");
    lockbox
        .add_file(&p("/secret.txt"), b"bravo", false)
        .unwrap();
    lockbox.commit().unwrap();
    let vault_password = SecretString::try_from_bytes(b"vault-password".to_vec()).unwrap();
    VaultDirectory::unlock_or_create(&vault_root, &vault_password)
        .unwrap()
        .store_key_directory_backup(
            lockbox.lockbox_id(),
            &VaultUnlock::export_key_directory_backup(&lockbox).unwrap(),
        )
        .unwrap();

    corrupt_key_directories(&path);

    let _vault_dir_guard = EnvVarGuard::set("LOCKBOX_VAULT_DIR", &vault_root);
    let _vault_password_guard = EnvVarGuard::set("LOCKBOX_VAULT_PASSWORD", "vault-password");
    let vault = Vault::new(MemoryStore::default());
    let opened = vault
        .unlock_lockbox(&path, LockboxUnlock::Password(&password))
        .unwrap();
    assert_eq!(opened.get_file(&p("/secret.txt")).unwrap(), b"bravo");

    let _ = fs::remove_file(path);
    let _ = fs::remove_dir_all(vault_root);
}

#[test]
fn vault_convenience_password_store_and_lock_all_flow() {
    let path = unique_path("password-convenience");
    let store = MemoryStore::default();
    let vault = Vault::new(store);
    assert!(vault.store().keys.borrow().is_empty());

    let password = SecretString::try_from_bytes(b"shared password".to_vec()).unwrap();
    let mut lockbox = vault
        .create_lockbox_with_password(&path, &password)
        .unwrap();
    lockbox
        .add_file(&p("/secret.txt"), b"charlie", false)
        .unwrap();
    lockbox.commit().unwrap();
    vault.lock_lockbox(&path).unwrap();
    assert!(matches!(
        vault.open_lockbox(&path),
        Err(Error::VaultUnavailable(_))
    ));

    let opened = vault
        .unlock_lockbox_with_password(&path, &password)
        .unwrap();
    assert_eq!(opened.get_file(&p("/secret.txt")).unwrap(), b"charlie");
    assert_eq!(
        vault
            .open_lockbox(&path)
            .unwrap()
            .get_file(&p("/secret.txt"))
            .unwrap(),
        b"charlie"
    );

    vault.lock_all().unwrap();
    assert!(matches!(
        vault.open_lockbox(&path),
        Err(Error::VaultUnavailable(_))
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn vault_directory_public_crud_helpers_flow() {
    let root = unique_dir("directory-crud");
    let vault_password = SecretString::try_from_bytes(b"vault-password".to_vec()).unwrap();
    let vault = VaultDirectory::unlock_or_create(&root, &vault_password).unwrap();
    assert_eq!(vault.root(), root.as_path());
    assert_eq!(vault.path(), root.join("local-vault.lbox").as_path());

    let keypair = RecipientKeyPair::generate().unwrap();
    assert!(!vault.private_key_exists("default").unwrap());
    vault.store_private_key("default", &keypair).unwrap();
    assert!(vault.private_key_exists("default").unwrap());
    assert_eq!(
        vault.list_private_keys().unwrap(),
        vec!["default".to_string()]
    );
    assert_eq!(
        vault
            .load_private_key("default")
            .unwrap()
            .private_key_record()
            .unwrap(),
        keypair.private_key_record().unwrap()
    );
    vault.delete_private_key("default").unwrap();
    assert!(!vault.private_key_exists("default").unwrap());

    let recipient = keypair.public_key();
    let signing = OwnerSigningKeyPair::generate().unwrap().public_key();
    assert!(!vault.contact_exists("alice").unwrap());
    vault.store_contact("alice", &recipient).unwrap();
    vault.store_contact_signing_key("alice", &signing).unwrap();
    assert!(vault.contact_exists("alice").unwrap());
    assert_eq!(vault.load_contact("alice").unwrap(), recipient);
    assert_eq!(vault.load_contact_signing_key("alice").unwrap(), signing);
    let recipients = vault.list_contacts().unwrap();
    assert_eq!(recipients.len(), 1);
    assert_eq!(recipients[0].name, "alice");
    assert_eq!(recipients[0].key, recipient);
    vault.delete_contact("alice").unwrap();
    assert!(!vault.contact_exists("alice").unwrap());
    assert!(vault.load_contact_signing_key("alice").is_err());

    assert_eq!(vault.key_directory_backup_count().unwrap(), 0);
    let password = SecretString::try_from_bytes(b"pw".to_vec()).unwrap();
    let lockbox_path = root.join("backup-count-source.lbox");
    let mut lockbox =
        Lockbox::create_file(&lockbox_path, LockboxProtection::Password(&password)).unwrap();
    lockbox.commit().unwrap();
    vault
        .store_key_directory_backup(
            lockbox.lockbox_id(),
            &VaultUnlock::export_key_directory_backup(&lockbox).unwrap(),
        )
        .unwrap();
    vault
        .store_key_directory_backup(
            lockbox.lockbox_id(),
            &VaultUnlock::export_key_directory_backup(&lockbox).unwrap(),
        )
        .unwrap();
    assert_eq!(vault.key_directory_backup_count().unwrap(), 1);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn vault_directory_tracks_identity_generations_and_rotation() {
    let root = unique_dir("identity-generations");
    let vault_password = SecretString::try_from_bytes(b"vault-password".to_vec()).unwrap();
    let vault = VaultDirectory::unlock_or_create(&root, &vault_password).unwrap();

    let original = RecipientKeyPair::generate().unwrap();
    vault.store_private_key("default", &original).unwrap();
    let original_signing_public = vault
        .load_owner_signing_key_generation("default", 1)
        .unwrap()
        .public_key()
        .to_bytes();

    let history = vault.list_identity_generations("default").unwrap();
    assert_eq!(history.active_generation, 1);
    assert_eq!(history.generations.len(), 1);
    assert_eq!(history.generations[0].index, 1);
    assert_eq!(
        history.generations[0].status,
        IdentityGenerationStatus::Active
    );
    assert_eq!(
        vault
            .load_private_key_generation("default", 1)
            .unwrap()
            .private_key_record()
            .unwrap(),
        original.private_key_record().unwrap()
    );
    assert_eq!(
        vault.list_private_keys().unwrap(),
        vec!["default".to_string()]
    );

    let rotated = vault.rotate_private_key("default").unwrap();
    assert_eq!(rotated.active_generation, 2);
    assert_eq!(rotated.generations.len(), 2);
    assert_eq!(
        rotated.generations[0].status,
        IdentityGenerationStatus::Retired
    );
    assert!(rotated.generations[0].retired_at_unix_ms.is_some());
    assert_eq!(
        rotated.generations[1].status,
        IdentityGenerationStatus::Active
    );
    assert_eq!(
        vault
            .load_private_key_generation("default", 1)
            .unwrap()
            .private_key_record()
            .unwrap(),
        original.private_key_record().unwrap()
    );
    let active = vault.load_private_key("default").unwrap();
    let active_signing_public = vault
        .load_owner_signing_key("default")
        .unwrap()
        .public_key()
        .to_bytes();
    assert_eq!(
        vault
            .load_private_key_generation("default", 2)
            .unwrap()
            .private_key_record()
            .unwrap(),
        active.private_key_record().unwrap()
    );
    assert_ne!(
        active.private_key_record().unwrap(),
        original.private_key_record().unwrap()
    );
    assert_eq!(
        vault
            .load_owner_signing_key_generation("default", 2)
            .unwrap()
            .public_key()
            .to_bytes(),
        active_signing_public
    );
    assert_ne!(active_signing_public, original_signing_public);
    assert_eq!(
        vault.list_private_keys().unwrap(),
        vec!["default".to_string()]
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn vault_directory_stores_identity_email_metadata() {
    let root = unique_dir("identity-email");
    let vault_password = SecretString::try_from_bytes(b"vault-password".to_vec()).unwrap();
    let vault = VaultDirectory::unlock_or_create(&root, &vault_password).unwrap();

    vault
        .store_private_key("default", &RecipientKeyPair::generate().unwrap())
        .unwrap();
    assert_eq!(vault.identity_email("default").unwrap(), None);

    vault
        .store_identity_email("default", "alice@example.test")
        .unwrap();
    assert_eq!(
        vault.identity_email("default").unwrap(),
        Some("alice@example.test".to_string())
    );

    vault.delete_private_key("default").unwrap();
    assert_eq!(vault.identity_email("default").unwrap(), None);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn private_key_file_import_uses_secure_import_path() {
    let root = unique_dir("private-key-file-import");
    fs::create_dir_all(&root).unwrap();
    let path = root.join("private.key");
    let keypair = RecipientKeyPair::generate().unwrap();
    let private = export_private_key(&keypair, KeyFormat::RawHex).unwrap();
    private
        .with_bytes(|bytes| fs::write(&path, bytes))
        .unwrap()
        .unwrap();

    let loaded = import_private_key_file(&path).unwrap();
    assert_eq!(
        loaded.private_key_record().unwrap(),
        keypair.private_key_record().unwrap()
    );

    let _ = fs::remove_dir_all(root);
}

fn unique_path(label: &str) -> PathBuf {
    unique_dir(label).join("test.lbox")
}

fn unique_dir(label: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/test-tmp")
        .join(format!(
            "lockbox-vault-api-{label}-{}-{}.lbox",
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

struct EnvVarGuard {
    name: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
}

fn corrupt_key_directories(path: &PathBuf) {
    let mut bytes = fs::read(path).unwrap();
    let magic = b"LBX2KEY\0";
    let mut offset = 0usize;
    while offset + magic.len() <= bytes.len() {
        if &bytes[offset..offset + magic.len()] == magic {
            bytes[offset] ^= 0x55;
            offset += magic.len();
        } else {
            offset += 1;
        }
    }
    fs::write(path, bytes).unwrap();
}
