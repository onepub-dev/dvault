use lockbox_core::{
    EnvName, Error, ListOptions, Lockbox, LockboxEntryKind, LockboxId, LockboxPath,
    LockboxProtection, LockboxUnlock, RecipientKeyPair, RecipientPublicKey, Result, SecretString,
    SecretVec,
};
use std::cell::RefCell;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::key_format::{export_private_key, import_private_key, KeyFormat};

const VAULT_FILE_NAME: &str = "local-vault.lbox";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTrustedRecipient {
    pub name: String,
    pub key: RecipientPublicKey,
}

#[derive(Debug)]
pub struct VaultDirectory {
    root: PathBuf,
    path: PathBuf,
    lockbox: RefCell<Lockbox>,
}

impl VaultDirectory {
    pub const DEFAULT_KEY_NAME: &'static str = "default";

    pub fn open_default(password: &SecretString) -> Result<Self> {
        Self::open(default_vault_dir()?, password)
    }

    pub fn open(root: impl AsRef<Path>, password: &SecretString) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        create_private_dir(&root)?;
        let path = root.join(VAULT_FILE_NAME);
        let lockbox = if path.exists() {
            Lockbox::open_file(&path, LockboxUnlock::Password(password))?
        } else {
            let lockbox = Lockbox::create_file(&path, LockboxProtection::Password(password))?;
            set_private_file_permissions(&path)?;
            lockbox
        };
        Ok(Self {
            root,
            path,
            lockbox: RefCell::new(lockbox),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn store_private_key(&self, name: &str, keypair: &RecipientKeyPair) -> Result<()> {
        let env_name = private_key_env_name(name)?;
        let seed = export_private_key(keypair, KeyFormat::RawHex)?;
        let value = SecretString::from_secure_vec(seed);
        self.put_secret_env_record(&env_name, &value)
    }

    pub fn load_private_key(&self, name: &str) -> Result<RecipientKeyPair> {
        let env_name = private_key_env_name(name)?;
        let secret = self
            .lockbox
            .borrow()
            .with_secret_env(&env_name, SecretString::try_clone)?
            .transpose()?
            .ok_or_else(|| Error::InvalidPath(format!("private key not found: {name}")))?;
        let mut bytes = SecretVec::new();
        secret.append_to_secure_vec(&mut bytes)?;
        import_private_key(bytes)
    }

    pub fn private_key_exists(&self, name: &str) -> Result<bool> {
        let lockbox = self.lockbox.borrow();
        Ok(lockbox
            .env_sensitivity(&private_key_env_name(name)?)?
            .is_some())
    }

    pub fn list_private_keys(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        let lockbox = self.lockbox.borrow();
        for (env_name, _) in lockbox.list_env()? {
            let Some(name) = private_key_name_from_env(&env_name) else {
                continue;
            };
            names.push(name?);
        }
        names.sort();
        names.dedup();
        Ok(names)
    }

    pub fn delete_private_key(&self, name: &str) -> Result<()> {
        self.delete_secret_env_record_if_exists(&private_key_env_name(name)?)
    }

    pub fn store_trusted_recipient(&self, name: &str, key: &RecipientPublicKey) -> Result<()> {
        self.put_record(&trusted_recipient_record_path(name)?, &key.to_bytes())
    }

    pub fn load_trusted_recipient(&self, name: &str) -> Result<RecipientPublicKey> {
        RecipientPublicKey::from_bytes(&self.get_record(&trusted_recipient_record_path(name)?)?)
    }

    pub fn trusted_recipient_exists(&self, name: &str) -> Result<bool> {
        Ok(self
            .lockbox
            .borrow()
            .stat(&trusted_recipient_record_path(name)?)
            .is_some())
    }

    pub fn delete_trusted_recipient(&self, name: &str) -> Result<()> {
        self.delete_record_if_exists(&trusted_recipient_record_path(name)?)
    }

    pub fn list_trusted_recipients(&self) -> Result<Vec<StoredTrustedRecipient>> {
        let mut out = Vec::new();
        for name in self.list_record_names("/trusted_recipients", ".pub")? {
            out.push(StoredTrustedRecipient {
                key: self.load_trusted_recipient(&name)?,
                name,
            });
        }
        Ok(out)
    }

    pub fn store_key_directory_backup(
        &self,
        lockbox_id: LockboxId,
        key_directory: &[u8],
    ) -> Result<()> {
        self.put_record(&key_directory_backup_record_path(lockbox_id), key_directory)
    }

    pub fn load_key_directory_backup(&self, lockbox_id: LockboxId) -> Result<Vec<u8>> {
        self.get_record(&key_directory_backup_record_path(lockbox_id))
    }

    pub fn key_directory_backup_count(&self) -> Result<usize> {
        Ok(self
            .lockbox
            .borrow()
            .list_iter(recursive_list("/key_directories"))?
            .filter_map(Result::ok)
            .filter(|entry| entry.kind == LockboxEntryKind::File)
            .count())
    }

    fn put_record(&self, path: &LockboxPath, bytes: &[u8]) -> Result<()> {
        let mut lockbox = self.lockbox.borrow_mut();
        lockbox.add_file(path, bytes, false)?;
        lockbox.commit()?;
        set_private_file_permissions(&self.path)?;
        Ok(())
    }

    fn put_secret_env_record(&self, name: &EnvName, value: &SecretString) -> Result<()> {
        let mut lockbox = self.lockbox.borrow_mut();
        lockbox.set_secret_env(name, value)?;
        lockbox.commit()?;
        set_private_file_permissions(&self.path)?;
        Ok(())
    }

    fn get_record(&self, path: &LockboxPath) -> Result<Vec<u8>> {
        self.lockbox.borrow().get_file(path)
    }

    fn delete_record_if_exists(&self, path: &LockboxPath) -> Result<()> {
        let mut lockbox = self.lockbox.borrow_mut();
        if lockbox.stat(path).is_some() {
            lockbox.delete(path)?;
            lockbox.commit()?;
            set_private_file_permissions(&self.path)?;
        }
        Ok(())
    }

    fn delete_secret_env_record_if_exists(&self, name: &EnvName) -> Result<()> {
        let mut lockbox = self.lockbox.borrow_mut();
        if lockbox.env_sensitivity(name)?.is_some() {
            lockbox.delete_env(name)?;
            lockbox.commit()?;
            set_private_file_permissions(&self.path)?;
        }
        Ok(())
    }

    fn list_record_names(&self, root: &str, extension: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in self.lockbox.borrow().list_iter(recursive_list(root))? {
            let entry = entry?;
            if entry.kind != LockboxEntryKind::File || !entry.path.ends_with(extension) {
                continue;
            }
            let name = entry
                .path
                .rsplit('/')
                .next()
                .and_then(|file| file.strip_suffix(extension))
                .ok_or_else(|| Error::InvalidPath(entry.path.to_string()))?;
            out.push(name.to_string());
        }
        out.sort();
        Ok(out)
    }
}

fn recursive_list(path: &str) -> ListOptions {
    let path = LockboxPath::new(path).expect("vault record roots are valid lockbox paths");
    let mut options = ListOptions::new(&path);
    options.recursive = true;
    options
}

fn private_key_env_name(name: &str) -> Result<EnvName> {
    let name = validate_record_name(name)?;
    EnvName::new(format!(
        "LOCKBOX_VAULT_PRIVATE_KEY_{}",
        encode_name_hex(name)
    ))
}

fn private_key_name_from_env(name: &str) -> Option<Result<String>> {
    let hex = name.strip_prefix("LOCKBOX_VAULT_PRIVATE_KEY_")?;
    Some(decode_name_hex(hex).ok_or_else(|| Error::InvalidPath(name.to_string())))
}

fn trusted_recipient_record_path(name: &str) -> Result<LockboxPath> {
    LockboxPath::new(format!(
        "/trusted_recipients/{}.pub",
        validate_record_name(name)?
    ))
}

fn key_directory_backup_record_path(lockbox_id: LockboxId) -> LockboxPath {
    LockboxPath::new(format!("/key_directories/{lockbox_id}.keydir"))
        .expect("key directory backup path is a valid lockbox path")
}

pub fn default_vault_dir() -> Result<PathBuf> {
    if let Ok(path) = env::var("LOCKBOX_VAULT_DIR") {
        return Ok(PathBuf::from(path));
    }
    default_vault_dir_for_os()
}

pub fn default_vault_path() -> Result<PathBuf> {
    Ok(default_vault_dir()?.join(VAULT_FILE_NAME))
}

#[cfg(target_os = "windows")]
fn default_vault_dir_for_os() -> Result<PathBuf> {
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| Error::Io("LOCALAPPDATA is not set".to_string()))?;
    Ok(base.join("Lockbox").join("vault"))
}

#[cfg(target_os = "macos")]
fn default_vault_dir_for_os() -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("Lockbox")
        .join("vault"))
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn default_vault_dir_for_os() -> Result<PathBuf> {
    if let Ok(path) = env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(path).join("lockbox").join("vault"));
    }
    Ok(home_dir()?
        .join(".local")
        .join("share")
        .join("lockbox")
        .join("vault"))
}

#[cfg(not(target_os = "windows"))]
fn home_dir() -> Result<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| Error::Io("HOME is not set".to_string()))
}

fn validate_record_name(name: &str) -> Result<&str> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(name)
    } else {
        Err(Error::InvalidPath(name.to_string()))
    }
}

fn encode_name_hex(name: &str) -> String {
    crate::encode_hex(name.as_bytes()).to_ascii_uppercase()
}

fn decode_name_hex(hex: &str) -> Option<String> {
    let bytes = crate::decode_hex(hex).ok()?;
    String::from_utf8(bytes).ok()
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|err| Error::Io(err.to_string()))?;
    set_private_dir_permissions(path)
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| Error::Io(err.to_string()))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|err| Error::Io(err.to_string()))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
