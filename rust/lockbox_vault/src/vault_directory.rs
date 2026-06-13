use lockbox_core::{
    Error, FormDefinition, FormFieldDefinition, FormTypeId, ListOptions, Lockbox, LockboxEntryKind,
    LockboxId, LockboxPath, LockboxProtection, LockboxUnlock, OwnerSigningKeyPair,
    OwnerSigningPublicKey, RecipientKeyPair, RecipientPublicKey, Result, SecretString, SecretVec,
    VariableName,
};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::key_format::{export_private_key, import_private_key, KeyFormat};

const VAULT_FILE_NAME: &str = "local-vault.lbox";
const VAULT_LOCK_FILE_NAME: &str = "local-vault.lbox.lock";
const VAULT_BACKUP_MAGIC: &[u8; 8] = b"LBVBK001";
const VAULT_STRUCTURE_VERSION_PATH: &str = "/vault/structure-version";
const KNOWN_LOCKBOX_MAGIC: &[u8; 4] = b"LBKL";
const KNOWN_LOCKBOX_VERSION: u16 = 1;
const IDENTITY_HISTORY_MAGIC: &[u8; 4] = b"LBIH";
const IDENTITY_HISTORY_VERSION: u16 = 1;
const IDENTITY_EMAIL_MAGIC: &[u8; 4] = b"LBIE";
const IDENTITY_EMAIL_VERSION: u16 = 1;
const GENERATION_ACTIVE: u16 = 1;
const GENERATION_RETIRED: u16 = 2;
const GENERATION_COMPROMISED: u16 = 3;

thread_local! {
    static VAULT_LOCK_DEPTH: Cell<usize> = const { Cell::new(0) };
}

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

/// Metadata stored in an encrypted vault backup archive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultBackupManifest {
    /// Backup archive format version.
    pub format_version: u16,

    /// Backup creation time.
    pub created_at_unix_ms: u64,

    /// Name of the encrypted vault file contained in the archive.
    pub vault_file_name: String,

    /// Number of bytes in the encrypted vault file.
    pub vault_size: u64,

    /// SHA-256 checksum of the encrypted vault file, encoded as lowercase hex.
    pub vault_sha256: String,
}

/// Password-protected local vault file for native reVault metadata.
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

    /// Replaces the default vault directory using `password`.
    ///
    /// The replacement is coordinated with the same interprocess lock used for
    /// vault backups and record writes.
    pub fn replace_default(password: &SecretString) -> Result<Self> {
        Self::replace(default_vault_dir()?, password)
    }

    /// Changes the pass phrase for the default vault directory.
    pub fn change_default_password(
        old_password: &SecretString,
        new_password: &SecretString,
    ) -> Result<()> {
        Self::change_password(default_vault_dir()?, old_password, new_password)
    }

    /// Changes the pass phrase for a vault directory.
    pub fn change_password(
        root: impl AsRef<Path>,
        old_password: &SecretString,
        new_password: &SecretString,
    ) -> Result<()> {
        let root = root.as_ref().to_path_buf();
        let path = root.join(VAULT_FILE_NAME);
        if !path.exists() {
            return Err(Error::VaultUnavailable(
                "local vault is not initialized; run `lockbox vault init` first".to_string(),
            ));
        }
        let _guard = VaultFileLock::acquire(&root)?;
        let mut lockbox = Lockbox::open_file(&path, LockboxUnlock::Password(old_password))?;
        lockbox.replace_password(old_password, new_password)?;
        set_private_file_permissions(&path)?;
        Ok(())
    }

    /// Replaces the vault directory at `root` using `password`.
    pub fn replace(root: impl AsRef<Path>, password: &SecretString) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        create_private_dir(&root)?;
        let _guard = VaultFileLock::acquire(&root)?;
        let path = root.join(VAULT_FILE_NAME);
        if path.exists() {
            fs::remove_file(&path).map_err(|err| Error::Io(err.to_string()))?;
        }
        let lockbox = Lockbox::create_file(&path, LockboxProtection::Password(password))?;
        set_private_file_permissions(&path)?;
        let vault = Self {
            root,
            path,
            lockbox: RefCell::new(lockbox),
        };
        vault.ensure_structure_version(true)?;
        Ok(vault)
    }

    /// Unlocks or creates a vault directory at `root`.
    ///
    /// The vault file is protected with `password`. When a new vault file is
    /// created, private file permissions are applied on supported platforms.
    pub fn unlock_or_create(root: impl AsRef<Path>, password: &SecretString) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        create_private_dir(&root)?;
        let _guard = VaultFileLock::acquire(&root)?;
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
        let variable_name = private_key_variable_name(name)?;
        let private_record = export_private_key(keypair, KeyFormat::RawHex)?;
        let value = SecretString::from_secure_vec(private_record);
        self.put_secret_variable_record(&variable_name, &value)?;
        if !self.owner_signing_key_exists(name)? {
            self.store_owner_signing_key_current_only(name, &OwnerSigningKeyPair::generate()?)?;
        }
        if self.read_identity_history(name)?.is_none() {
            self.store_private_key_generation(name, 1, keypair)?;
            let signing_key = self.load_owner_signing_key(name)?;
            self.store_owner_signing_key_generation(name, 1, &signing_key)?;
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
        let variable_name = private_key_variable_name(name)?;
        let secret = self
            .lockbox
            .borrow()
            .with_secret_variable(&variable_name, SecretString::try_clone)?
            .transpose()?
            .ok_or_else(|| Error::NotFound(format!("vault private key {name}")))?;
        let mut bytes = SecretVec::new();
        secret.append_to_secure_vec(&mut bytes)?;
        import_private_key(bytes)
    }

    /// Loads the owner signing key associated with a vault identity.
    ///
    /// Older vault identities did not have a separate signing key. The first
    /// load lazily creates one so future lockbox commits can be signed without
    /// deriving signing material from the lockbox content key.
    pub fn load_owner_signing_key(&self, name: &str) -> Result<OwnerSigningKeyPair> {
        if !self.owner_signing_key_exists(name)? {
            self.store_owner_signing_key_current_only(name, &OwnerSigningKeyPair::generate()?)?;
        }
        self.load_owner_signing_key_existing(name)
    }

    /// Returns whether a private key exists under `name`.
    pub fn private_key_exists(&self, name: &str) -> Result<bool> {
        let lockbox = self.lockbox.borrow();
        Ok(lockbox
            .variable_sensitivity(&private_key_variable_name(name)?)?
            .is_some())
    }

    /// Lists private-key names stored in this vault.
    pub fn list_private_keys(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        let lockbox = self.lockbox.borrow();
        for (variable_name, _) in lockbox.list_variables()? {
            let Some(name) = private_key_name_from_variable(&variable_name) else {
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
                self.delete_secret_variable_record_if_exists(
                    &private_key_generation_variable_name(name, generation.index)?,
                )?;
                self.delete_secret_variable_record_if_exists(
                    &owner_signing_key_generation_variable_name(name, generation.index)?,
                )?;
            }
            self.delete_record_if_exists(&identity_history_record_path(name)?)?;
        }
        self.delete_record_if_exists(&identity_email_record_path(name)?)?;
        self.delete_secret_variable_record_if_exists(&owner_signing_key_variable_name(name)?)?;
        self.delete_secret_variable_record_if_exists(&private_key_variable_name(name)?)
    }

    /// Stores the public email address associated with a vault identity.
    pub fn store_identity_email(&self, name: &str, email: &str) -> Result<()> {
        if !self.private_key_exists(name)? {
            return Err(Error::NotFound(format!("vault private key {name}")));
        }
        self.put_record_replace(
            &identity_email_record_path(name)?,
            &encode_identity_email(email),
        )
    }

    /// Loads the public email address associated with a vault identity.
    pub fn identity_email(&self, name: &str) -> Result<Option<String>> {
        let path = identity_email_record_path(name)?;
        {
            let lockbox = self.lockbox.borrow();
            if lockbox.stat(&path).is_none() {
                return Ok(None);
            }
        }
        decode_identity_email(&self.get_record(&path)?).map(Some)
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
        let signing_key = OwnerSigningKeyPair::generate()?;
        self.store_private_key_current_only(name, &keypair)?;
        self.store_owner_signing_key_current_only(name, &signing_key)?;
        self.store_private_key_generation(name, new_index, &keypair)?;
        self.store_owner_signing_key_generation(name, new_index, &signing_key)?;
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
        let variable_name = private_key_generation_variable_name(name, index)?;
        let secret = self
            .lockbox
            .borrow()
            .with_secret_variable(&variable_name, SecretString::try_clone)?
            .transpose()?
            .ok_or_else(|| {
                Error::NotFound(format!("vault private key {name} generation {index}"))
            })?;
        let mut bytes = SecretVec::new();
        secret.append_to_secure_vec(&mut bytes)?;
        import_private_key(bytes)
    }

    /// Loads one owner signing-key generation by index.
    pub fn load_owner_signing_key_generation(
        &self,
        name: &str,
        index: u16,
    ) -> Result<OwnerSigningKeyPair> {
        let variable_name = owner_signing_key_generation_variable_name(name, index)?;
        let secret = self
            .lockbox
            .borrow()
            .with_secret_variable(&variable_name, SecretString::try_clone)?
            .transpose()?
            .ok_or_else(|| {
                Error::NotFound(format!("vault owner signing key {name} generation {index}"))
            })?;
        let mut bytes = SecretVec::new();
        secret.append_to_secure_vec(&mut bytes)?;
        decode_hex_secret_in_place(&mut bytes)?;
        OwnerSigningKeyPair::from_private_key_record(bytes)
    }

    /// Stores a trusted recipient public key under `name`.
    ///
    /// Names must contain only ASCII letters, digits, `-`, or `_`.
    pub fn store_trusted_recipient(&self, name: &str, key: &RecipientPublicKey) -> Result<()> {
        self.put_record(&trusted_recipient_record_path(name)?, &key.to_bytes())
    }

    /// Stores the trusted signing public key associated with a contact.
    pub fn store_trusted_recipient_signing_key(
        &self,
        name: &str,
        key: &OwnerSigningPublicKey,
    ) -> Result<()> {
        self.put_record_replace(
            &trusted_recipient_signing_record_path(name)?,
            &key.to_bytes(),
        )
    }

    /// Loads a trusted recipient public key by name.
    pub fn load_trusted_recipient(&self, name: &str) -> Result<RecipientPublicKey> {
        RecipientPublicKey::from_bytes(&self.get_record(&trusted_recipient_record_path(name)?)?)
    }

    /// Loads the trusted signing public key associated with a contact.
    pub fn load_trusted_recipient_signing_key(&self, name: &str) -> Result<OwnerSigningPublicKey> {
        OwnerSigningPublicKey::from_bytes(
            &self.get_record(&trusted_recipient_signing_record_path(name)?)?,
        )
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
        self.delete_record_if_exists(&trusted_recipient_signing_record_path(name)?)?;
        self.delete_record_if_exists(&trusted_recipient_record_path(name)?)
    }

    /// Lists trusted recipients stored in this vault.
    pub fn list_trusted_recipients(&self) -> Result<Vec<StoredTrustedRecipient>> {
        let mut out = Vec::new();
        for name in self.list_record_names("/trusted_recipients", ".pub")? {
            if name.ends_with(".signing") {
                continue;
            }
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

    /// Creates or revises a reusable form definition stored in the vault.
    pub fn define_form(
        &self,
        alias: &str,
        name: &str,
        fields: Vec<FormFieldDefinition>,
    ) -> Result<FormDefinition> {
        let _guard = VaultFileLock::acquire(&self.root)?;
        let mut lockbox = self.lockbox.borrow_mut();
        let definition = lockbox.define_form(alias, name, fields)?;
        lockbox.commit()?;
        set_private_file_permissions(&self.path)?;
        Ok(definition)
    }

    /// Creates or revises a reusable form definition with a stable definition id.
    pub fn define_form_with_type_id(
        &self,
        type_id: FormTypeId,
        alias: &str,
        name: &str,
        fields: Vec<FormFieldDefinition>,
    ) -> Result<FormDefinition> {
        let _guard = VaultFileLock::acquire(&self.root)?;
        let mut lockbox = self.lockbox.borrow_mut();
        let definition = lockbox.define_form_with_type_id(type_id, alias, name, fields)?;
        lockbox.commit()?;
        set_private_file_permissions(&self.path)?;
        Ok(definition)
    }

    /// Imports an exact reusable form definition into the vault.
    pub fn import_form_definition(&self, definition: FormDefinition) -> Result<FormDefinition> {
        let _guard = VaultFileLock::acquire(&self.root)?;
        let mut lockbox = self.lockbox.borrow_mut();
        let definition = lockbox.import_form_definition(definition)?;
        lockbox.commit()?;
        set_private_file_permissions(&self.path)?;
        Ok(definition)
    }

    /// Resolves a reusable vault form definition by alias or definition id.
    pub fn resolve_form_definition(&self, reference: &str) -> Result<FormDefinition> {
        self.lockbox.borrow().resolve_form_definition(reference)
    }

    /// Lists reusable form definitions stored in the vault.
    pub fn list_form_definitions(&self) -> Result<Vec<FormDefinition>> {
        self.lockbox.borrow().list_form_definitions()
    }

    /// Stores a lockbox pass phrase in the vault, keyed by lockbox id.
    pub fn remember_lockbox_password(
        &self,
        lockbox_id: LockboxId,
        password: &SecretString,
    ) -> Result<()> {
        self.put_secret_variable_record(&lockbox_password_variable_name(lockbox_id)?, password)
    }

    /// Loads a remembered lockbox pass phrase, if one exists for this lockbox id.
    pub fn remembered_lockbox_password(
        &self,
        lockbox_id: LockboxId,
    ) -> Result<Option<SecretString>> {
        Ok(self
            .lockbox
            .borrow()
            .with_secret_variable(
                &lockbox_password_variable_name(lockbox_id)?,
                SecretString::try_clone,
            )?
            .transpose()?)
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
        let _guard = VaultFileLock::acquire(&self.root)?;
        let mut lockbox = self.lockbox.borrow_mut();
        let replace = replace && lockbox.stat(path).is_some();
        lockbox.add_file(path, bytes, replace)?;
        lockbox.commit()?;
        set_private_file_permissions(&self.path)?;
        Ok(())
    }

    fn put_secret_variable_record(&self, name: &VariableName, value: &SecretString) -> Result<()> {
        let _guard = VaultFileLock::acquire(&self.root)?;
        let mut lockbox = self.lockbox.borrow_mut();
        lockbox.set_secret_variable(name, value)?;
        lockbox.commit()?;
        set_private_file_permissions(&self.path)?;
        Ok(())
    }

    fn get_record(&self, path: &LockboxPath) -> Result<Vec<u8>> {
        self.lockbox.borrow().get_file(path)
    }

    fn delete_record_if_exists(&self, path: &LockboxPath) -> Result<()> {
        let _guard = VaultFileLock::acquire(&self.root)?;
        let mut lockbox = self.lockbox.borrow_mut();
        if lockbox.stat(path).is_some() {
            lockbox.delete(path)?;
            lockbox.commit()?;
            set_private_file_permissions(&self.path)?;
        }
        Ok(())
    }

    fn delete_secret_variable_record_if_exists(&self, name: &VariableName) -> Result<()> {
        let _guard = VaultFileLock::acquire(&self.root)?;
        let mut lockbox = self.lockbox.borrow_mut();
        if lockbox.variable_sensitivity(name)?.is_some() {
            lockbox.delete_variable(name)?;
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
                    "local vault structure version {version} is newer than this reVault build supports ({CURRENT_VAULT_STRUCTURE_VERSION}); upgrade reVault before using this vault"
                )))
            }
            Some(version) => Err(Error::Configuration(format!(
                "local vault structure version {version} cannot be migrated by this reVault build"
            ))),
            None if initialize_missing => self.write_structure_version(CURRENT_VAULT_STRUCTURE_VERSION),
            None => Err(Error::Configuration(
                "local vault structure version is missing; recreate the vault with this reVault build"
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
        self.put_secret_variable_record(&private_key_variable_name(name)?, &value)
    }

    fn owner_signing_key_exists(&self, name: &str) -> Result<bool> {
        let lockbox = self.lockbox.borrow();
        Ok(lockbox
            .variable_sensitivity(&owner_signing_key_variable_name(name)?)?
            .is_some())
    }

    fn load_owner_signing_key_existing(&self, name: &str) -> Result<OwnerSigningKeyPair> {
        let secret = self
            .lockbox
            .borrow()
            .with_secret_variable(
                &owner_signing_key_variable_name(name)?,
                SecretString::try_clone,
            )?
            .transpose()?
            .ok_or_else(|| Error::NotFound(format!("vault owner signing key {name}")))?;
        let mut bytes = SecretVec::new();
        secret.append_to_secure_vec(&mut bytes)?;
        decode_hex_secret_in_place(&mut bytes)?;
        OwnerSigningKeyPair::from_private_key_record(bytes)
    }

    fn store_owner_signing_key_current_only(
        &self,
        name: &str,
        keypair: &OwnerSigningKeyPair,
    ) -> Result<()> {
        let value =
            SecretString::from_secure_vec(hex_encode_secret(keypair.private_key_record()?)?);
        self.put_secret_variable_record(&owner_signing_key_variable_name(name)?, &value)
    }

    fn store_private_key_generation(
        &self,
        name: &str,
        index: u16,
        keypair: &RecipientKeyPair,
    ) -> Result<()> {
        let private_record = export_private_key(keypair, KeyFormat::RawHex)?;
        let value = SecretString::from_secure_vec(private_record);
        self.put_secret_variable_record(&private_key_generation_variable_name(name, index)?, &value)
    }

    fn store_owner_signing_key_generation(
        &self,
        name: &str,
        index: u16,
        keypair: &OwnerSigningKeyPair,
    ) -> Result<()> {
        let value =
            SecretString::from_secure_vec(hex_encode_secret(keypair.private_key_record()?)?);
        self.put_secret_variable_record(
            &owner_signing_key_generation_variable_name(name, index)?,
            &value,
        )
    }

    fn ensure_identity_history(&self, name: &str) -> Result<IdentityHistory> {
        if let Some(history) = self.read_identity_history(name)? {
            return Ok(history);
        }
        let keypair = self.load_private_key(name)?;
        self.store_private_key_generation(name, 1, &keypair)?;
        let signing_key = self.load_owner_signing_key(name)?;
        self.store_owner_signing_key_generation(name, 1, &signing_key)?;
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

/// Writes a consistent encrypted backup archive for the default local vault.
///
/// The archive contains the raw encrypted `local-vault.lbox` bytes plus a JSON
/// manifest and checksum. It does not decrypt or export vault records.
pub fn backup_default_vault(
    output: impl AsRef<Path>,
    overwrite: bool,
) -> Result<VaultBackupManifest> {
    let root = default_vault_dir()?;
    let path = root.join(VAULT_FILE_NAME);
    if !path.exists() {
        return Err(Error::VaultUnavailable(
            "local vault is not initialized; run `lockbox vault init` first".to_string(),
        ));
    }
    let _guard = VaultFileLock::acquire(&root)?;
    let vault_bytes = fs::read(&path).map_err(|err| Error::Io(err.to_string()))?;
    let digest: [u8; 32] = Sha256::digest(&vault_bytes).into();
    let manifest = VaultBackupManifest {
        format_version: 1,
        created_at_unix_ms: unix_ms(SystemTime::now()),
        vault_file_name: VAULT_FILE_NAME.to_string(),
        vault_size: vault_bytes.len() as u64,
        vault_sha256: crate::encode_hex(&digest),
    };
    write_vault_backup_archive(output.as_ref(), overwrite, &manifest, &vault_bytes)?;
    Ok(manifest)
}

/// Restores the default local vault from an encrypted backup archive.
///
/// The archive checksum is verified before the existing vault file is replaced.
pub fn restore_default_vault(
    input: impl AsRef<Path>,
    overwrite: bool,
) -> Result<VaultBackupManifest> {
    let (manifest, vault_bytes) = read_vault_backup_archive(input.as_ref())?;
    let root = default_vault_dir()?;
    create_private_dir(&root)?;
    let path = root.join(VAULT_FILE_NAME);
    let _guard = VaultFileLock::acquire(&root)?;
    if path.exists() && !overwrite {
        return Err(Error::AlreadyExists(format!(
            "{}; pass --overwrite to replace it",
            path.display()
        )));
    }
    let tmp = root.join("local-vault.lbox.restore.tmp");
    fs::write(&tmp, vault_bytes).map_err(|err| Error::Io(err.to_string()))?;
    set_private_file_permissions(&tmp)?;
    if path.exists() {
        fs::remove_file(&path).map_err(|err| Error::Io(err.to_string()))?;
    }
    fs::rename(&tmp, &path).map_err(|err| Error::Io(err.to_string()))?;
    set_private_file_permissions(&path)?;
    Ok(manifest)
}

fn write_vault_backup_archive(
    output: &Path,
    overwrite: bool,
    manifest: &VaultBackupManifest,
    vault_bytes: &[u8],
) -> Result<()> {
    if output.exists() && !overwrite {
        return Err(Error::AlreadyExists(format!(
            "{}; pass --overwrite to replace it",
            output.display()
        )));
    }
    let manifest_bytes = serde_json::to_vec(manifest).map_err(|err| Error::Io(err.to_string()))?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    if !overwrite {
        options.create_new(true);
    }
    let mut file = options
        .open(output)
        .map_err(|err| Error::Io(err.to_string()))?;
    file.write_all(VAULT_BACKUP_MAGIC)
        .map_err(|err| Error::Io(err.to_string()))?;
    file.write_all(&(manifest_bytes.len() as u64).to_be_bytes())
        .map_err(|err| Error::Io(err.to_string()))?;
    file.write_all(&manifest_bytes)
        .map_err(|err| Error::Io(err.to_string()))?;
    file.write_all(vault_bytes)
        .map_err(|err| Error::Io(err.to_string()))?;
    file.sync_all().map_err(|err| Error::Io(err.to_string()))
}

fn read_vault_backup_archive(input: &Path) -> Result<(VaultBackupManifest, Vec<u8>)> {
    let mut file = File::open(input).map_err(|err| Error::Io(err.to_string()))?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)
        .map_err(|err| Error::Io(err.to_string()))?;
    if &magic != VAULT_BACKUP_MAGIC {
        return Err(Error::InvalidInput(
            "backup file is not a reVault vault backup archive".to_string(),
        ));
    }
    let mut len = [0u8; 8];
    file.read_exact(&mut len)
        .map_err(|err| Error::Io(err.to_string()))?;
    let manifest_len = u64::from_be_bytes(len);
    if manifest_len > 1024 * 1024 {
        return Err(Error::SecurityLimitExceeded(
            "vault backup manifest is too large".to_string(),
        ));
    }
    let mut manifest_bytes = vec![0u8; manifest_len as usize];
    file.read_exact(&mut manifest_bytes)
        .map_err(|err| Error::Io(err.to_string()))?;
    let manifest: VaultBackupManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|err| Error::InvalidInput(err.to_string()))?;
    if manifest.format_version != 1 {
        return Err(Error::InvalidInput(format!(
            "vault backup format version {} is not supported",
            manifest.format_version
        )));
    }
    if manifest.vault_file_name != VAULT_FILE_NAME {
        return Err(Error::InvalidInput(format!(
            "vault backup contains unexpected file {}",
            manifest.vault_file_name
        )));
    }
    let mut vault_bytes = Vec::new();
    file.read_to_end(&mut vault_bytes)
        .map_err(|err| Error::Io(err.to_string()))?;
    if vault_bytes.len() as u64 != manifest.vault_size {
        return Err(Error::InvalidInput(
            "vault backup size does not match manifest".to_string(),
        ));
    }
    let digest: [u8; 32] = Sha256::digest(&vault_bytes).into();
    if crate::encode_hex(&digest) != manifest.vault_sha256 {
        return Err(Error::InvalidInput(
            "vault backup checksum does not match manifest".to_string(),
        ));
    }
    Ok((manifest, vault_bytes))
}

struct VaultFileLock {
    #[cfg(unix)]
    file: Option<File>,
    #[cfg(not(unix))]
    path: Option<PathBuf>,
    active: bool,
}

impl VaultFileLock {
    fn acquire(root: &Path) -> Result<Self> {
        let nested = VAULT_LOCK_DEPTH.with(|depth| {
            let value = depth.get();
            depth.set(value.saturating_add(1));
            value > 0
        });
        if nested {
            return Ok(Self {
                #[cfg(unix)]
                file: None,
                #[cfg(not(unix))]
                path: None,
                active: true,
            });
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;

            let path = root.join(VAULT_LOCK_FILE_NAME);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)
                .map_err(|err| {
                    VAULT_LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
                    Error::Io(err.to_string())
                })?;
            // SAFETY: flock operates on a valid file descriptor owned by `file`.
            // The descriptor remains open for the lifetime of the guard.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                VAULT_LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
                return Err(Error::Io(std::io::Error::last_os_error().to_string()));
            }
            Ok(Self {
                file: Some(file),
                active: true,
            })
        }
        #[cfg(not(unix))]
        {
            let path = root.join(VAULT_LOCK_FILE_NAME);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|err| {
                    VAULT_LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
                    if err.kind() == std::io::ErrorKind::AlreadyExists {
                        Error::VaultUnavailable(
                            "local vault is locked by another process".to_string(),
                        )
                    } else {
                        Error::Io(err.to_string())
                    }
                })?;
            file.write_all(std::process::id().to_string().as_bytes())
                .map_err(|err| {
                    VAULT_LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
                    Error::Io(err.to_string())
                })?;
            Ok(Self {
                path: Some(path),
                active: true,
            })
        }
    }
}

impl Drop for VaultFileLock {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        #[cfg(unix)]
        if let Some(file) = &self.file {
            use std::os::fd::AsRawFd;

            // SAFETY: this unlocks the same valid descriptor locked in `acquire`.
            let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        }
        #[cfg(not(unix))]
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
        VAULT_LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

fn recursive_list(path: &str) -> ListOptions {
    let path = LockboxPath::new(path).expect("vault record roots are valid lockbox paths");
    let mut options = ListOptions::new(&path);
    options.recursive = true;
    options
}

fn private_key_variable_name(name: &str) -> Result<VariableName> {
    let name = validate_record_name(name)?;
    VariableName::new(format!(
        "LOCKBOX_VAULT_PRIVATE_KEY_{}",
        encode_name_hex(name)
    ))
}

fn private_key_generation_variable_name(name: &str, index: u16) -> Result<VariableName> {
    let name = validate_record_name(name)?;
    VariableName::new(format!(
        "LOCKBOX_VAULT_PRIVATE_KEY_{}_GEN_{index:04}",
        encode_name_hex(name)
    ))
}

fn owner_signing_key_variable_name(name: &str) -> Result<VariableName> {
    let name = validate_record_name(name)?;
    VariableName::new(format!(
        "LOCKBOX_VAULT_SIGNING_KEY_{}",
        encode_name_hex(name)
    ))
}

fn owner_signing_key_generation_variable_name(name: &str, index: u16) -> Result<VariableName> {
    let name = validate_record_name(name)?;
    VariableName::new(format!(
        "LOCKBOX_VAULT_SIGNING_KEY_{}_GEN_{index:04}",
        encode_name_hex(name)
    ))
}

fn private_key_name_from_variable(name: &str) -> Option<Result<String>> {
    let name = name.strip_prefix('/').unwrap_or(name);
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

fn trusted_recipient_signing_record_path(name: &str) -> Result<LockboxPath> {
    LockboxPath::new(format!(
        "/trusted_recipients/{}.signing.pub",
        validate_record_name(name)?
    ))
}

fn identity_history_record_path(name: &str) -> Result<LockboxPath> {
    LockboxPath::new(format!(
        "/identity_histories/{}.lbih",
        validate_record_name(name)?
    ))
}

fn identity_email_record_path(name: &str) -> Result<LockboxPath> {
    LockboxPath::new(format!(
        "/identity_emails/{}.lbie",
        validate_record_name(name)?
    ))
}

fn key_directory_backup_record_path(lockbox_id: LockboxId) -> LockboxPath {
    LockboxPath::new(format!("/key_directories/{lockbox_id}.keydir"))
        .expect("key directory backup path is a valid lockbox path")
}

fn lockbox_password_variable_name(lockbox_id: LockboxId) -> Result<VariableName> {
    VariableName::new(format!(
        "LOCKBOX_VAULT_LOCKBOX_PASSWORD_{}",
        crate::encode_hex(lockbox_id.as_bytes())
    ))
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

fn hex_encode_secret(mut bytes: SecretVec) -> Result<SecretVec> {
    let original_len = bytes.len();
    bytes.resize_zeroed(original_len * 2)?;
    bytes.with_mut_bytes(|bytes| {
        for index in (0..original_len).rev() {
            let byte = bytes[index];
            bytes[index * 2] = secret_hex_char(byte >> 4);
            bytes[index * 2 + 1] = secret_hex_char(byte & 0x0f);
        }
    })?;
    Ok(bytes)
}

fn decode_hex_secret_in_place(bytes: &mut SecretVec) -> Result<()> {
    bytes.with_mut_bytes(|bytes| {
        let len = bytes.len();
        if len % 2 != 0 {
            return Err(Error::InvalidKeyMaterial(
                "owner signing key hex has odd length".to_string(),
            ));
        }
        let mut write = 0usize;
        let mut read = 0usize;
        while read < len {
            let high = secret_hex_digit(bytes[read])?;
            let low = secret_hex_digit(bytes[read + 1])?;
            bytes[write] = (high << 4) | low;
            write += 1;
            read += 2;
        }
        for byte in &mut bytes[write..] {
            *byte = 0;
        }
        Ok::<_, Error>(write)
    })??;
    bytes.truncate(bytes.len() / 2)?;
    Ok(())
}

fn secret_hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidKeyMaterial(
            "owner signing key hex contains non-hex digits".to_string(),
        )),
    }
}

fn secret_hex_char(value: u8) -> u8 {
    b"0123456789abcdef"[value as usize]
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

fn encode_identity_email(email: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(IDENTITY_EMAIL_MAGIC);
    put_u16(&mut out, IDENTITY_EMAIL_VERSION);
    put_string(&mut out, email);
    out
}

fn decode_identity_email(bytes: &[u8]) -> Result<String> {
    let mut reader = BinaryReader::new(bytes);
    if reader.bytes(4)? != IDENTITY_EMAIL_MAGIC {
        return Err(Error::CorruptVaultRecord(
            "identity email record has invalid magic".to_string(),
        ));
    }
    let version = reader.u16()?;
    if version != IDENTITY_EMAIL_VERSION {
        return Err(Error::CorruptVaultRecord(format!(
            "identity email record version {version} is not supported"
        )));
    }
    let email = reader.string()?;
    reader.finish()?;
    Ok(email)
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
    Ok(base.join("reVault").join("vault"))
}

#[cfg(target_os = "macos")]
fn default_vault_dir_for_os() -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("reVault")
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
