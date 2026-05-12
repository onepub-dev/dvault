use lockbox_core::{
    EntryKind, Error, ListOptions, Lockbox, LockboxCreate, LockboxId, LockboxUnlock, MlKemKeyPair,
    MlKemRecipientKey, Result, SecretString,
};
use std::cell::RefCell;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const VAULT_FILE_NAME: &str = "local-vault.lbox";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTrustedRecipient {
    pub name: String,
    pub key: MlKemRecipientKey,
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
            Lockbox::open_file(
                &path,
                LockboxUnlock::Password(password.expose_bytes().to_vec()),
            )?
        } else {
            let lockbox = Lockbox::create_file(
                &path,
                LockboxCreate::Password(password.expose_bytes().to_vec()),
            )?;
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

    pub fn store_private_key(&self, name: &str, keypair: &MlKemKeyPair) -> Result<()> {
        self.put_record(&private_key_record_path(name)?, &keypair.to_seed_bytes())
    }

    pub fn load_private_key(&self, name: &str) -> Result<MlKemKeyPair> {
        MlKemKeyPair::from_seed_bytes(&self.get_record(&private_key_record_path(name)?)?)
    }

    pub fn private_key_exists(&self, name: &str) -> Result<bool> {
        Ok(self
            .lockbox
            .borrow()
            .stat(&private_key_record_path(name)?)
            .is_some())
    }

    pub fn list_private_keys(&self) -> Result<Vec<String>> {
        self.list_record_names("/private_keys", ".key")
    }

    pub fn delete_private_key(&self, name: &str) -> Result<()> {
        self.delete_record_if_exists(&private_key_record_path(name)?)
    }

    pub fn store_trusted_recipient(&self, name: &str, key: &MlKemRecipientKey) -> Result<()> {
        self.put_record(&trusted_recipient_record_path(name)?, &key.to_bytes())
    }

    pub fn load_trusted_recipient(&self, name: &str) -> Result<MlKemRecipientKey> {
        MlKemRecipientKey::from_bytes(&self.get_record(&trusted_recipient_record_path(name)?)?)
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
            .filter(|entry| entry.kind == EntryKind::File)
            .count())
    }

    fn put_record(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let mut lockbox = self.lockbox.borrow_mut();
        lockbox.put_file(path, bytes)?;
        lockbox.commit()?;
        set_private_file_permissions(&self.path)?;
        Ok(())
    }

    fn get_record(&self, path: &str) -> Result<Vec<u8>> {
        self.lockbox.borrow().get_file(path)
    }

    fn delete_record_if_exists(&self, path: &str) -> Result<()> {
        let mut lockbox = self.lockbox.borrow_mut();
        if lockbox.stat(path).is_some() {
            lockbox.delete(path)?;
            lockbox.commit()?;
            set_private_file_permissions(&self.path)?;
        }
        Ok(())
    }

    fn list_record_names(&self, root: &str, extension: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in self.lockbox.borrow().list_iter(recursive_list(root))? {
            let entry = entry?;
            if entry.kind != EntryKind::File || !entry.path.ends_with(extension) {
                continue;
            }
            let name = entry
                .path
                .rsplit('/')
                .next()
                .and_then(|file| file.strip_suffix(extension))
                .ok_or_else(|| Error::InvalidPath(entry.path.clone()))?;
            out.push(name.to_string());
        }
        out.sort();
        Ok(out)
    }
}

fn recursive_list(path: &str) -> ListOptions {
    let mut options = ListOptions::new(path);
    options.recursive = true;
    options
}

fn private_key_record_path(name: &str) -> Result<String> {
    Ok(format!("/private_keys/{}.key", validate_record_name(name)?))
}

fn trusted_recipient_record_path(name: &str) -> Result<String> {
    Ok(format!(
        "/trusted_recipients/{}.pub",
        validate_record_name(name)?
    ))
}

fn key_directory_backup_record_path(lockbox_id: LockboxId) -> String {
    format!("/key_directories/{lockbox_id}.keydir")
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
