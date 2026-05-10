use lockbox_core::{Error, Lockbox, LockboxCreate, LockboxUnlock, MlKemKeyPair, Result};
use lockbox_vault::{ContentKeyStore, Vault, VaultDirectory};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Default)]
struct MemoryStore {
    keys: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl ContentKeyStore for MemoryStore {
    fn get_content_key(&self, lockbox_id: lockbox_core::LockboxId) -> Result<Option<Vec<u8>>> {
        Ok(self.keys.borrow().get(&lockbox_id.to_string()).cloned())
    }

    fn put_content_key(&self, lockbox_id: lockbox_core::LockboxId, key: &[u8]) -> Result<()> {
        self.keys
            .borrow_mut()
            .insert(lockbox_id.to_string(), key.to_vec());
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
fn vault_create_open_and_lock_with_raw_key() {
    let path = unique_path("raw");
    let vault = Vault::new(MemoryStore::default());
    let key = b"0123456789abcdef0123456789abcdef".to_vec();

    let mut lockbox = vault
        .create_lockbox(&path, LockboxCreate::RawKey(key))
        .unwrap();
    lockbox.put_file("/docs/a.txt", b"alpha").unwrap();
    lockbox.commit().unwrap();

    let opened = vault.open_lockbox(&path).unwrap();
    assert_eq!(opened.get_file("/docs/a.txt").unwrap(), b"alpha");

    vault.lock_lockbox(&path).unwrap();
    assert!(matches!(vault.open_lockbox(&path), Err(Error::InvalidKey)));

    let _ = fs::remove_file(path);
}

#[test]
fn vault_unlock_populates_cache_for_password_lockbox() {
    let path = unique_path("password");
    let vault = Vault::new(MemoryStore::default());
    let password = b"shared password".to_vec();

    let mut lockbox = vault
        .create_lockbox(&path, LockboxCreate::Password(password.clone()))
        .unwrap();
    lockbox.put_file("/secret.txt", b"bravo").unwrap();
    lockbox.commit().unwrap();
    vault.lock_lockbox(&path).unwrap();

    assert!(matches!(vault.open_lockbox(&path), Err(Error::InvalidKey)));

    vault
        .unlock_lockbox(&path, LockboxUnlock::Password(password))
        .unwrap();
    let opened = vault.open_lockbox(&path).unwrap();
    assert_eq!(opened.get_file("/secret.txt").unwrap(), b"bravo");

    let _ = fs::remove_file(path);
}

#[test]
fn vault_directory_stores_local_keys_trusted_recipients_and_key_directory_backups() {
    let root = unique_dir("directory");
    let vault = VaultDirectory::open(&root).unwrap();
    let keypair = MlKemKeyPair::generate();

    vault.store_private_key("default", &keypair).unwrap();
    let loaded = vault.load_private_key("default").unwrap();
    assert_eq!(loaded.to_seed_bytes(), keypair.to_seed_bytes());

    vault
        .store_trusted_recipient("alice", &keypair.recipient_key())
        .unwrap();
    let trusted = vault.list_trusted_recipients().unwrap();
    assert_eq!(trusted.len(), 1);
    assert_eq!(trusted[0].name, "alice");

    let mut lockbox = Lockbox::create_with_password(b"pw").unwrap();
    lockbox.put_file("/a.txt", b"alpha").unwrap();
    lockbox.commit().unwrap();
    let backup = lockbox.export_key_directory_backup().unwrap();
    vault
        .store_key_directory_backup(lockbox.lockbox_id(), &backup)
        .unwrap();
    assert_eq!(
        vault
            .load_key_directory_backup(lockbox.lockbox_id())
            .unwrap(),
        backup
    );

    let _ = fs::remove_dir_all(root);
}

fn unique_path(label: &str) -> PathBuf {
    unique_dir(label).join("test.lbox")
}

fn unique_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
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
