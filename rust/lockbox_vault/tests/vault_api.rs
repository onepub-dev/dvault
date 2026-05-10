use lockbox_core::{Error, Lockbox, LockboxCreate, LockboxUnlock, MlKemKeyPair, Result};
use lockbox_vault::{ContentKeyStore, SecretString, Vault, VaultDirectory};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

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
    let passphrase = SecretString::from_bytes(b"private-key-password".to_vec());

    vault
        .store_private_key("default", &keypair, &passphrase)
        .unwrap();
    let encrypted = fs::read(root.join("private_keys").join("default.key")).unwrap();
    assert!(encrypted.starts_with(b"LBXVKEY1"));
    assert!(!String::from_utf8_lossy(&encrypted).contains("private-key-password"));
    let loaded = vault.load_private_key("default", &passphrase).unwrap();
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

#[test]
fn vault_unlock_uses_key_directory_backup_when_embedded_directory_is_corrupt() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let path = unique_path("backup-fallback");
    let vault_root = unique_dir("backup-fallback-vault");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir_all(&vault_root);

    std::env::set_var("LOCKBOX_VAULT_DIR", &vault_root);

    let password = b"shared password".to_vec();
    let mut lockbox = Lockbox::create_file(&path, LockboxCreate::Password(password.clone()))
        .expect("create password lockbox");
    lockbox.put_file("/secret.txt", b"bravo").unwrap();
    lockbox.commit().unwrap();
    VaultDirectory::open(&vault_root)
        .unwrap()
        .store_key_directory_backup(
            lockbox.lockbox_id(),
            &lockbox.export_key_directory_backup().unwrap(),
        )
        .unwrap();

    corrupt_key_directories(&path);

    let vault = Vault::new(MemoryStore::default());
    let opened = vault
        .unlock_lockbox(&path, LockboxUnlock::Password(password))
        .unwrap();
    assert_eq!(opened.get_file("/secret.txt").unwrap(), b"bravo");

    std::env::remove_var("LOCKBOX_VAULT_DIR");
    let _ = fs::remove_file(path);
    let _ = fs::remove_dir_all(vault_root);
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
