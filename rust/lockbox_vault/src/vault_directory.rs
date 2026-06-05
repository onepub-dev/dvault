use lockbox_core::{
    EnvName, Error, ListOptions, Lockbox, LockboxEntryKind, LockboxId, LockboxPath,
    LockboxProtection, LockboxUnlock, RecipientKeyPair, RecipientPublicKey, Result, SecretString,
    SecretVec,
};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::key_format::{export_private_key, import_private_key, KeyFormat};

const VAULT_FILE_NAME: &str = "local-vault.lbox";
const VAULT_STRUCTURE_VERSION_PATH: &str = "/vault/structure-version";
const KNOWN_LOCKBOX_MAGIC: &[u8; 4] = b"LBKL";
const KNOWN_LOCKBOX_VERSION: u16 = 1;
const IDENTITY_HISTORY_MAGIC: &[u8; 4] = b"LBIH";
const IDENTITY_HISTORY_VERSION: u16 = 1;
const GENERATION_ACTIVE: u16 = 1;
const GENERATION_RETIRED: u16 = 2;
const GENERATION_COMPROMISED: u16 = 3;

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

/// Lockbox path remembered by the local vault for diagnostics and bulk access
/// refresh operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownLockbox {
    /// Stable id embedded in the lockbox.
    pub lockbox_id: LockboxId,

    /// Path used when this lockbox was last seen.
    pub path: String,

    /// Last time this record was updated.
    pub last_seen_unix_ms: u64,
}

/// One generation of a vault identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityGeneration {
    pub index: u16,
    pub status: IdentityGenerationStatus,
    pub recipient_fingerprint: Vec<u8>,
    pub created_at_unix_ms: u64,
    pub retired_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityGenerationStatus {
    Active,
    Retired,
    Compromised,
}

/// Versioned identity history for one vault identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityHistory {
    pub name: String,
    pub active_generation: u16,
    pub generations: Vec<IdentityGeneration>,
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
        let existed = path.exists();
        let lockbox = if existed {
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
        vault.ensure_structure_version(!existed)?;
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
        let private_record = export_private_key(keypair, KeyFormat::RawHex)?;
        let value = SecretString::from_secure_vec(private_record);
        self.put_secret_env_record(&env_name, &value)?;
        if self.read_identity_history(name)?.is_none() {
            self.store_private_key_generation(name, 1, keypair)?;
            let now = unix_ms(SystemTime::now());
            self.write_identity_history(&IdentityHistory {
                name: name.to_string(),
                active_generation: 1,
                generations: vec![IdentityGeneration {
                    index: 1,
                    status: IdentityGenerationStatus::Active,
                    recipient_fingerprint: recipient_fingerprint(&keypair.public_key()),
                    created_at_unix_ms: now,
                    retired_at_unix_ms: None,
                }],
            })?;
        }
        Ok(())
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
        if let Some(history) = self.read_identity_history(name)? {
            for generation in history.generations {
                self.delete_secret_env_record_if_exists(&private_key_generation_env_name(
                    name,
                    generation.index,
                )?)?;
            }
            self.delete_record_if_exists(&identity_history_record_path(name)?)?;
        }
        self.delete_secret_env_record_if_exists(&private_key_env_name(name)?)
    }

    /// Lists identity generations for a private key, creating generation one
    /// for existing pre-history identities.
    pub fn list_identity_generations(&self, name: &str) -> Result<IdentityHistory> {
        self.ensure_identity_history(name)
    }

    /// Rotates a vault identity to a new active key generation.
    pub fn rotate_private_key(&self, name: &str) -> Result<IdentityHistory> {
        let mut history = self.ensure_identity_history(name)?;
        let now = unix_ms(SystemTime::now());
        for generation in &mut history.generations {
            if generation.status == IdentityGenerationStatus::Active {
                generation.status = IdentityGenerationStatus::Retired;
                generation.retired_at_unix_ms = Some(now);
            }
        }
        let new_index = history
            .generations
            .iter()
            .map(|generation| generation.index)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let keypair = RecipientKeyPair::generate()?;
        self.store_private_key_current_only(name, &keypair)?;
        self.store_private_key_generation(name, new_index, &keypair)?;
        history.active_generation = new_index;
        history.generations.push(IdentityGeneration {
            index: new_index,
            status: IdentityGenerationStatus::Active,
            recipient_fingerprint: recipient_fingerprint(&keypair.public_key()),
            created_at_unix_ms: now,
            retired_at_unix_ms: None,
        });
        self.write_identity_history(&history)?;
        Ok(history)
    }

    /// Loads one identity generation by index.
    pub fn load_private_key_generation(&self, name: &str, index: u16) -> Result<RecipientKeyPair> {
        let env_name = private_key_generation_env_name(name, index)?;
        let secret = self
            .lockbox
            .borrow()
            .with_secret_env(&env_name, SecretString::try_clone)?
            .transpose()?
            .ok_or_else(|| {
                Error::NotFound(format!("vault private key {name} generation {index}"))
            })?;
        let mut bytes = SecretVec::new();
        secret.append_to_secure_vec(&mut bytes)?;
        import_private_key(bytes)
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

    /// Remembers a lockbox path for diagnostics and future bulk access refresh.
    pub fn remember_known_lockbox(
        &self,
        lockbox_id: LockboxId,
        path: impl AsRef<Path>,
    ) -> Result<()> {
        let path = path.as_ref().to_string_lossy().to_string();
        let record = KnownLockbox {
            lockbox_id,
            path,
            last_seen_unix_ms: unix_ms(SystemTime::now()),
        };
        self.put_record_replace(
            &known_lockbox_record_path(record.path.as_str())?,
            &encode_known_lockbox(&record),
        )
    }

    /// Lists lockboxes remembered by the local vault.
    pub fn list_known_lockboxes(&self) -> Result<Vec<KnownLockbox>> {
        let mut out = Vec::new();
        for name in self.list_record_names("/known_lockboxes", ".lkl")? {
            let path = LockboxPath::new(format!("/known_lockboxes/{name}.lkl"))?;
            out.push(decode_known_lockbox(&self.get_record(&path)?)?);
        }
        out.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(out)
    }

    /// Removes one remembered lockbox path. The lockbox file itself is not
    /// deleted or modified.
    pub fn forget_known_lockbox(&self, path: impl AsRef<Path>) -> Result<()> {
        self.delete_record_if_exists(&known_lockbox_record_path(path.as_ref())?)
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

    fn ensure_structure_version(&self, initialize_missing: bool) -> Result<()> {
        match self.read_structure_version()? {
            Some(CURRENT_VAULT_STRUCTURE_VERSION) => Ok(()),
            Some(version) if version > CURRENT_VAULT_STRUCTURE_VERSION => {
                Err(Error::Configuration(format!(
                    "local vault structure version {version} is newer than this Lockbox build supports ({CURRENT_VAULT_STRUCTURE_VERSION}); upgrade Lockbox before using this vault"
                )))
            }
            Some(version) => Err(Error::Configuration(format!(
                "local vault structure version {version} cannot be migrated by this Lockbox build"
            ))),
            None if initialize_missing => self.write_structure_version(CURRENT_VAULT_STRUCTURE_VERSION),
            None => Err(Error::Configuration(
                "local vault structure version is missing; recreate the vault with this Lockbox build"
                    .to_string(),
            )),
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

    fn store_private_key_current_only(&self, name: &str, keypair: &RecipientKeyPair) -> Result<()> {
        let private_record = export_private_key(keypair, KeyFormat::RawHex)?;
        let value = SecretString::from_secure_vec(private_record);
        self.put_secret_env_record(&private_key_env_name(name)?, &value)
    }

    fn store_private_key_generation(
        &self,
        name: &str,
        index: u16,
        keypair: &RecipientKeyPair,
    ) -> Result<()> {
        let private_record = export_private_key(keypair, KeyFormat::RawHex)?;
        let value = SecretString::from_secure_vec(private_record);
        self.put_secret_env_record(&private_key_generation_env_name(name, index)?, &value)
    }

    fn ensure_identity_history(&self, name: &str) -> Result<IdentityHistory> {
        if let Some(history) = self.read_identity_history(name)? {
            return Ok(history);
        }
        let keypair = self.load_private_key(name)?;
        self.store_private_key_generation(name, 1, &keypair)?;
        let history = IdentityHistory {
            name: name.to_string(),
            active_generation: 1,
            generations: vec![IdentityGeneration {
                index: 1,
                status: IdentityGenerationStatus::Active,
                recipient_fingerprint: recipient_fingerprint(&keypair.public_key()),
                created_at_unix_ms: unix_ms(SystemTime::now()),
                retired_at_unix_ms: None,
            }],
        };
        self.write_identity_history(&history)?;
        Ok(history)
    }

    fn read_identity_history(&self, name: &str) -> Result<Option<IdentityHistory>> {
        let path = identity_history_record_path(name)?;
        {
            let lockbox = self.lockbox.borrow();
            if lockbox.stat(&path).is_none() {
                return Ok(None);
            }
        }
        decode_identity_history(name, &self.get_record(&path)?).map(Some)
    }

    fn write_identity_history(&self, history: &IdentityHistory) -> Result<()> {
        self.put_record_replace(
            &identity_history_record_path(&history.name)?,
            &encode_identity_history(history),
        )
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

fn private_key_generation_env_name(name: &str, index: u16) -> Result<EnvName> {
    let name = validate_record_name(name)?;
    EnvName::new(format!(
        "LOCKBOX_VAULT_PRIVATE_KEY_{}_GEN_{index:04}",
        encode_name_hex(name)
    ))
}

fn private_key_name_from_env(name: &str) -> Option<Result<String>> {
    let hex = name.strip_prefix("LOCKBOX_VAULT_PRIVATE_KEY_")?;
    if hex.contains("_GEN_") {
        return None;
    }
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

fn identity_history_record_path(name: &str) -> Result<LockboxPath> {
    LockboxPath::new(format!(
        "/identity_histories/{}.lbih",
        validate_record_name(name)?
    ))
}

fn key_directory_backup_record_path(lockbox_id: LockboxId) -> LockboxPath {
    LockboxPath::new(format!("/key_directories/{lockbox_id}.keydir"))
        .expect("key directory backup path is a valid lockbox path")
}

fn known_lockbox_record_path(path: impl AsRef<Path>) -> Result<LockboxPath> {
    let mut hasher = Sha256::new();
    hasher.update(path.as_ref().to_string_lossy().as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let encoded = crate::encode_hex(&digest);
    LockboxPath::new(format!("/known_lockboxes/{encoded}.lkl"))
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

fn encode_known_lockbox(record: &KnownLockbox) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(KNOWN_LOCKBOX_MAGIC);
    put_u16(&mut out, KNOWN_LOCKBOX_VERSION);
    out.extend_from_slice(record.lockbox_id.as_bytes());
    put_string(&mut out, &record.path);
    put_u64(&mut out, record.last_seen_unix_ms);
    out
}

fn decode_known_lockbox(bytes: &[u8]) -> Result<KnownLockbox> {
    let mut reader = BinaryReader::new(bytes);
    if reader.bytes(4)? != KNOWN_LOCKBOX_MAGIC {
        return Err(Error::CorruptVaultRecord(
            "known lockbox record has invalid magic".to_string(),
        ));
    }
    let version = reader.u16()?;
    if version != KNOWN_LOCKBOX_VERSION {
        return Err(Error::CorruptVaultRecord(format!(
            "known lockbox record version {version} is not supported"
        )));
    }
    let id = reader.bytes(16)?;
    let lockbox_id = LockboxId::from_bytes(id.try_into().map_err(|_| {
        Error::CorruptVaultRecord("known lockbox id has invalid length".to_string())
    })?);
    let path = reader.string()?;
    let last_seen_unix_ms = reader.u64()?;
    reader.finish()?;
    Ok(KnownLockbox {
        lockbox_id,
        path,
        last_seen_unix_ms,
    })
}

fn encode_identity_history(history: &IdentityHistory) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(IDENTITY_HISTORY_MAGIC);
    put_u16(&mut out, IDENTITY_HISTORY_VERSION);
    put_u16(&mut out, history.active_generation);
    put_u16(&mut out, history.generations.len() as u16);
    for generation in &history.generations {
        put_u16(&mut out, generation.index);
        put_u16(&mut out, generation_status_to_u16(generation.status));
        put_u64(&mut out, generation.created_at_unix_ms);
        match generation.retired_at_unix_ms {
            Some(retired_at) => {
                out.push(1);
                put_u64(&mut out, retired_at);
            }
            None => {
                out.push(0);
                put_u64(&mut out, 0);
            }
        }
        put_bytes(&mut out, &generation.recipient_fingerprint);
    }
    out
}

fn decode_identity_history(name: &str, bytes: &[u8]) -> Result<IdentityHistory> {
    let mut reader = BinaryReader::new(bytes);
    if reader.bytes(4)? != IDENTITY_HISTORY_MAGIC {
        return Err(Error::CorruptVaultRecord(
            "identity history record has invalid magic".to_string(),
        ));
    }
    let version = reader.u16()?;
    if version != IDENTITY_HISTORY_VERSION {
        return Err(Error::CorruptVaultRecord(format!(
            "identity history version {version} is not supported"
        )));
    }
    let active_generation = reader.u16()?;
    let count = reader.u16()? as usize;
    let mut generations = Vec::with_capacity(count);
    for _ in 0..count {
        let index = reader.u16()?;
        let status = generation_status_from_u16(reader.u16()?)?;
        let created_at_unix_ms = reader.u64()?;
        let retired_present = reader.u8()? != 0;
        let retired_at = reader.u64()?;
        let recipient_fingerprint = reader.length_prefixed_bytes()?.to_vec();
        generations.push(IdentityGeneration {
            index,
            status,
            recipient_fingerprint,
            created_at_unix_ms,
            retired_at_unix_ms: retired_present.then_some(retired_at),
        });
    }
    reader.finish()?;
    Ok(IdentityHistory {
        name: name.to_string(),
        active_generation,
        generations,
    })
}

struct BinaryReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.offset + len > self.bytes.len() {
            return Err(Error::CorruptVaultRecord(
                "binary vault record is truncated".to_string(),
            ));
        }
        let out = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes = self.bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes = self.bytes(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn string(&mut self) -> Result<String> {
        let len = self.u32()? as usize;
        let bytes = self.bytes(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| {
            Error::CorruptVaultRecord("binary vault string is not valid UTF-8".to_string())
        })
    }

    fn length_prefixed_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }

    fn finish(&self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(Error::CorruptVaultRecord(
                "binary vault record has trailing bytes".to_string(),
            ));
        }
        Ok(())
    }
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    put_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

fn generation_status_to_u16(status: IdentityGenerationStatus) -> u16 {
    match status {
        IdentityGenerationStatus::Active => GENERATION_ACTIVE,
        IdentityGenerationStatus::Retired => GENERATION_RETIRED,
        IdentityGenerationStatus::Compromised => GENERATION_COMPROMISED,
    }
}

fn generation_status_from_u16(value: u16) -> Result<IdentityGenerationStatus> {
    match value {
        GENERATION_ACTIVE => Ok(IdentityGenerationStatus::Active),
        GENERATION_RETIRED => Ok(IdentityGenerationStatus::Retired),
        GENERATION_COMPROMISED => Ok(IdentityGenerationStatus::Compromised),
        _ => Err(Error::CorruptVaultRecord(format!(
            "unknown identity generation status {value}"
        ))),
    }
}

fn recipient_fingerprint(public_key: &RecipientPublicKey) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(public_key.to_bytes());
    hasher.finalize()[..16].to_vec()
}

fn unix_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
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
