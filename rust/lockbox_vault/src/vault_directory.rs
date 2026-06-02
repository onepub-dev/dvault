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
const VAULT_STRUCTURE_VERSION_PATH: &str = "/vault/structure-version";

/// Current on-disk structure version for records stored inside the local vault.
pub const CURRENT_VAULT_STRUCTURE_VERSION: u32 = 1;

/// Trusted recipient entry stored in a `VaultDirectory`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTrustedRecipient {
    /// User-assigned recipient name.
    pub name: String,

    /// Recipient public key associated with `name`.
    pub key: RecipientPublicKey,
}

/// Password-protected local vault file for native Lockbox metadata.
///
/// A `VaultDirectory` stores its data in `local-vault.lbox` under a private
/// directory. It can hold recipient private keys, trusted recipient public keys,
/// and key-directory backups used by `Vault` recovery fallback paths.
#[derive(Debug)]
pub struct VaultDirectory {
    root: PathBuf,
    path: PathBuf,
    lockbox: RefCell<Lockbox>,
}

impl VaultDirectory {
    /// Default name used for the primary local recipient key.
    pub const DEFAULT_KEY_NAME: &'static str = "default";

    /// Unlocks or creates the default vault directory using `password`.
    ///
    /// The directory is chosen by `default_vault_dir`.
    pub fn unlock_or_create_default(password: &SecretString) -> Result<Self> {
        Self::unlock_or_create(default_vault_dir()?, password)
    }

    /// Unlocks or creates a vault directory at `root`.
    ///
    /// The vault file is protected with `password`. When a new vault file is
    /// created, private file permissions are applied on supported platforms.
    pub fn unlock_or_create(root: impl AsRef<Path>, password: &SecretString) -> Result<Self> {
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
        let vault = Self {
            root,
            path,
            lockbox: RefCell::new(lockbox),
        };
        vault.ensure_structure_version()?;
        Ok(vault)
    }

    /// Returns the root directory that contains the local vault file.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the path to the `local-vault.lbox` file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the structure version recorded inside this vault.
    pub fn structure_version(&self) -> Result<u32> {
        self.read_structure_version()?.ok_or_else(|| {
            Error::CorruptVaultRecord("vault structure version record is missing".to_string())
        })
    }

    /// Stores a recipient private key under `name`.
    ///
    /// Names must contain only ASCII letters, digits, `-`, or `_`.
    pub fn store_private_key(&self, name: &str, keypair: &RecipientKeyPair) -> Result<()> {
        let env_name = private_key_env_name(name)?;
        let seed = export_private_key(keypair, KeyFormat::RawHex)?;
        let value = SecretString::from_secure_vec(seed);
        self.put_secret_env_record(&env_name, &value)
    }

    /// Loads a recipient private key previously stored under `name`.
    pub fn load_private_key(&self, name: &str) -> Result<RecipientKeyPair> {
        let env_name = private_key_env_name(name)?;
        let secret = self
            .lockbox
            .borrow()
            .with_secret_env(&env_name, SecretString::try_clone)?
            .transpose()?
            .ok_or_else(|| Error::NotFound(format!("vault private key {name}")))?;
        let mut bytes = SecretVec::new();
        secret.append_to_secure_vec(&mut bytes)?;
        import_private_key(bytes)
    }

    /// Returns whether a private key exists under `name`.
    pub fn private_key_exists(&self, name: &str) -> Result<bool> {
        let lockbox = self.lockbox.borrow();
        Ok(lockbox
            .env_sensitivity(&private_key_env_name(name)?)?
            .is_some())
    }

    /// Lists private-key names stored in this vault.
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

    /// Deletes the private key stored under `name`, if present.
    pub fn delete_private_key(&self, name: &str) -> Result<()> {
        self.delete_secret_env_record_if_exists(&private_key_env_name(name)?)
    }

    /// Stores a trusted recipient public key under `name`.
    ///
    /// Names must contain only ASCII letters, digits, `-`, or `_`.
    pub fn store_trusted_recipient(&self, name: &str, key: &RecipientPublicKey) -> Result<()> {
        self.put_record(&trusted_recipient_record_path(name)?, &key.to_bytes())
    }

    /// Loads a trusted recipient public key by name.
    pub fn load_trusted_recipient(&self, name: &str) -> Result<RecipientPublicKey> {
        RecipientPublicKey::from_bytes(&self.get_record(&trusted_recipient_record_path(name)?)?)
    }

    /// Returns whether a trusted recipient exists under `name`.
    pub fn trusted_recipient_exists(&self, name: &str) -> Result<bool> {
        Ok(self
            .lockbox
            .borrow()
            .stat(&trusted_recipient_record_path(name)?)
            .is_some())
    }

    /// Deletes the trusted recipient stored under `name`, if present.
    pub fn delete_trusted_recipient(&self, name: &str) -> Result<()> {
        self.delete_record_if_exists(&trusted_recipient_record_path(name)?)
    }

    /// Lists trusted recipients stored in this vault.
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

    /// Stores an exported key-directory backup for `lockbox_id`.
    ///
    /// Backups can be used by `Vault` to recover unlockability when the
    /// embedded key directory in a lockbox file is damaged.
    pub fn store_key_directory_backup(
        &self,
        lockbox_id: LockboxId,
        key_directory: &[u8],
    ) -> Result<()> {
        self.put_record_replace(&key_directory_backup_record_path(lockbox_id), key_directory)
    }

    /// Loads the key-directory backup for `lockbox_id`.
    pub fn load_key_directory_backup(&self, lockbox_id: LockboxId) -> Result<Vec<u8>> {
        self.get_record(&key_directory_backup_record_path(lockbox_id))
    }

    /// Counts key-directory backups stored in this vault.
    pub fn key_directory_backup_count(&self) -> Result<usize> {
        Ok(self
            .lockbox
            .borrow()
            .list(recursive_list("/key_directories"))?
            .filter_map(Result::ok)
            .filter(|entry| entry.kind == LockboxEntryKind::File)
            .count())
    }

    fn put_record(&self, path: &LockboxPath, bytes: &[u8]) -> Result<()> {
        self.put_record_with_replace(path, bytes, false)
    }

    fn put_record_replace(&self, path: &LockboxPath, bytes: &[u8]) -> Result<()> {
        self.put_record_with_replace(path, bytes, true)
    }

    fn put_record_with_replace(
        &self,
        path: &LockboxPath,
        bytes: &[u8],
        replace: bool,
    ) -> Result<()> {
        let mut lockbox = self.lockbox.borrow_mut();
        let replace = replace && lockbox.stat(path).is_some();
        lockbox.add_file(path, bytes, replace)?;
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
        for entry in self.lockbox.borrow().list(recursive_list(root))? {
            let entry = entry?;
            if entry.kind != LockboxEntryKind::File || !entry.path.ends_with(extension) {
                continue;
            }
            let name = entry
                .path
                .rsplit('/')
                .next()
                .and_then(|file| file.strip_suffix(extension))
                .ok_or_else(|| {
                    Error::CorruptVaultRecord(format!(
                        "record path {} does not end with expected extension {extension}",
                        entry.path
                    ))
                })?;
            out.push(name.to_string());
        }
        out.sort();
        Ok(out)
    }

    fn ensure_structure_version(&self) -> Result<()> {
        match self.read_structure_version()? {
            Some(CURRENT_VAULT_STRUCTURE_VERSION) => Ok(()),
            Some(version) if version > CURRENT_VAULT_STRUCTURE_VERSION => {
                Err(Error::Configuration(format!(
                    "local vault structure version {version} is newer than this Lockbox build supports ({CURRENT_VAULT_STRUCTURE_VERSION}); upgrade Lockbox before using this vault"
                )))
            }
            Some(version) => self.migrate_structure_version(version),
            None => self.write_structure_version(CURRENT_VAULT_STRUCTURE_VERSION),
        }
    }

    fn migrate_structure_version(&self, version: u32) -> Result<()> {
        match version {
            0 => self.write_structure_version(CURRENT_VAULT_STRUCTURE_VERSION),
            version => Err(Error::Configuration(format!(
                "local vault structure version {version} cannot be migrated by this Lockbox build"
            ))),
        }
    }

    fn read_structure_version(&self) -> Result<Option<u32>> {
        let path = vault_structure_version_record_path();
        {
            let lockbox = self.lockbox.borrow();
            if lockbox.stat(&path).is_none() {
                return Ok(None);
            }
        }
        decode_structure_version(&self.get_record(&path)?).map(Some)
    }

    fn write_structure_version(&self, version: u32) -> Result<()> {
        let bytes = format!("{version}\n");
        self.put_record_replace(&vault_structure_version_record_path(), bytes.as_bytes())
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
    Some(decode_name_hex(hex).ok_or_else(|| {
        Error::CorruptVaultRecord(format!("private key record name is not valid hex: {name}"))
    }))
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

fn vault_structure_version_record_path() -> LockboxPath {
    LockboxPath::new(VAULT_STRUCTURE_VERSION_PATH)
        .expect("vault structure version path is a valid lockbox path")
}

fn decode_structure_version(bytes: &[u8]) -> Result<u32> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        Error::CorruptVaultRecord("vault structure version is not valid UTF-8".to_string())
    })?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::CorruptVaultRecord(
            "vault structure version is not a decimal integer".to_string(),
        ));
    }
    text.parse::<u32>()
        .map_err(|_| Error::CorruptVaultRecord("vault structure version is too large".to_string()))
}

/// Returns the default directory for the local vault.
///
/// `LOCKBOX_VAULT_DIR` overrides the platform default. Without an override,
/// the path follows the operating system's application-data conventions.
pub fn default_vault_dir() -> Result<PathBuf> {
    if let Ok(path) = env::var("LOCKBOX_VAULT_DIR") {
        return Ok(PathBuf::from(path));
    }
    default_vault_dir_for_os()
}

/// Returns the default path to the local vault file.
pub fn default_vault_path() -> Result<PathBuf> {
    Ok(default_vault_dir()?.join(VAULT_FILE_NAME))
}

#[cfg(target_os = "windows")]
fn default_vault_dir_for_os() -> Result<PathBuf> {
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| Error::Configuration("LOCALAPPDATA is not set".to_string()))?;
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
        .ok_or_else(|| Error::Configuration("HOME is not set".to_string()))
}

fn validate_record_name(name: &str) -> Result<&str> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(name)
    } else {
        Err(Error::InvalidInput(format!(
            "vault record name must contain only ASCII letters, digits, '-' or '_': {name}"
        )))
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
