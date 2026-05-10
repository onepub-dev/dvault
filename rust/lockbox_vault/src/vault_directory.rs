use lockbox_core::{Error, LockboxId, MlKemKeyPair, MlKemRecipientKey, Result};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{decode_hex, encode_hex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTrustedRecipient {
    pub name: String,
    pub key: MlKemRecipientKey,
}

#[derive(Debug, Clone)]
pub struct VaultDirectory {
    root: PathBuf,
}

impl VaultDirectory {
    pub const DEFAULT_KEY_NAME: &'static str = "default";

    pub fn open_default() -> Result<Self> {
        Self::open(default_vault_dir()?)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        create_private_dir(&root)?;
        create_private_dir(&root.join("private_keys"))?;
        create_private_dir(&root.join("trusted_recipients"))?;
        create_private_dir(&root.join("key_directories"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn store_private_key(&self, name: &str, keypair: &MlKemKeyPair) -> Result<()> {
        let path = self.private_key_path(name)?;
        write_private_file(&path, encode_hex(&keypair.to_seed_bytes()).as_bytes())
    }

    pub fn load_private_key(&self, name: &str) -> Result<MlKemKeyPair> {
        let bytes = read_hex_file(&self.private_key_path(name)?)?;
        MlKemKeyPair::from_seed_bytes(&bytes)
    }

    pub fn private_key_exists(&self, name: &str) -> Result<bool> {
        Ok(self.private_key_path(name)?.exists())
    }

    pub fn list_private_keys(&self) -> Result<Vec<String>> {
        list_record_names(&self.root.join("private_keys"), "key")
    }

    pub fn store_trusted_recipient(&self, name: &str, key: &MlKemRecipientKey) -> Result<()> {
        let path = self.trusted_recipient_path(name)?;
        write_private_file(&path, encode_hex(&key.to_bytes()).as_bytes())
    }

    pub fn load_trusted_recipient(&self, name: &str) -> Result<MlKemRecipientKey> {
        let bytes = read_hex_file(&self.trusted_recipient_path(name)?)?;
        MlKemRecipientKey::from_bytes(&bytes)
    }

    pub fn list_trusted_recipients(&self) -> Result<Vec<StoredTrustedRecipient>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.root.join("trusted_recipients"))
            .map_err(|err| Error::Io(err.to_string()))?
        {
            let entry = entry.map_err(|err| Error::Io(err.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("pub") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            out.push(StoredTrustedRecipient {
                name: stem.to_string(),
                key: MlKemRecipientKey::from_bytes(&read_hex_file(&path)?)?,
            });
        }
        out.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(out)
    }

    pub fn store_key_directory_backup(
        &self,
        lockbox_id: LockboxId,
        key_directory: &[u8],
    ) -> Result<()> {
        let path = self.key_directory_backup_path(lockbox_id);
        write_private_file(&path, key_directory)
    }

    pub fn load_key_directory_backup(&self, lockbox_id: LockboxId) -> Result<Vec<u8>> {
        fs::read(self.key_directory_backup_path(lockbox_id))
            .map_err(|err| Error::Io(err.to_string()))
    }

    fn private_key_path(&self, name: &str) -> Result<PathBuf> {
        Ok(self
            .root
            .join("private_keys")
            .join(format!("{}.key", validate_record_name(name)?)))
    }

    fn trusted_recipient_path(&self, name: &str) -> Result<PathBuf> {
        Ok(self
            .root
            .join("trusted_recipients")
            .join(format!("{}.pub", validate_record_name(name)?)))
    }

    fn key_directory_backup_path(&self, lockbox_id: LockboxId) -> PathBuf {
        self.root
            .join("key_directories")
            .join(format!("{lockbox_id}.keydir"))
    }
}

pub fn default_vault_dir() -> Result<PathBuf> {
    if let Ok(path) = env::var("LOCKBOX_VAULT_DIR") {
        return Ok(PathBuf::from(path));
    }
    default_vault_dir_for_os()
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

fn list_record_names(dir: &Path, extension: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(|err| Error::Io(err.to_string()))? {
        let entry = entry.map_err(|err| Error::Io(err.to_string()))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some(extension) {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|value| value.to_str()) {
            out.push(stem.to_string());
        }
    }
    out.sort();
    Ok(out)
}

fn read_hex_file(path: &Path) -> Result<Vec<u8>> {
    let text = fs::read_to_string(path).map_err(|err| Error::Io(err.to_string()))?;
    decode_hex(text.trim()).map_err(|err| Error::Io(err.to_string()))
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

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).map_err(|err| Error::Io(err.to_string()))?;
    set_private_file_permissions(path)
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
