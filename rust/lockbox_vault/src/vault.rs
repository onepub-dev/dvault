use lockbox_core::vault_bridge::{UnlockedContentKey, VaultUnlock};
use lockbox_core::{Error, Lockbox, LockboxCreate, LockboxUnlock, Result, SecretString, SecretVec};
use std::path::Path;

use crate::{AgentClient, ContentKeyStore, VaultDirectory};

pub type LocalVault = Vault<AgentClient>;

pub fn local_vault() -> LocalVault {
    Vault::new(AgentClient)
}

#[derive(Debug, Clone)]
pub struct Vault<S = AgentClient> {
    store: S,
}

impl<S> Vault<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }
}

impl<S: ContentKeyStore> Vault<S> {
    pub fn create_lockbox_with_password(
        &self,
        path: impl AsRef<Path>,
        password: &SecretString,
    ) -> Result<Lockbox> {
        self.create_lockbox(path, LockboxCreate::Password(password))
    }

    pub fn unlock_lockbox_with_password(
        &self,
        path: impl AsRef<Path>,
        password: &SecretString,
    ) -> Result<Lockbox> {
        self.unlock_lockbox(path, LockboxUnlock::Password(password))
    }

    pub fn create_lockbox(
        &self,
        path: impl AsRef<Path>,
        protection: LockboxCreate<'_>,
    ) -> Result<Lockbox> {
        let path = path.as_ref();
        match protection {
            LockboxCreate::ContentKey(key) => {
                let store_key = key.try_clone()?;
                let lockbox = Lockbox::create_file(path, LockboxCreate::ContentKey(key))?;
                store_key
                    .with_bytes(|key| self.store.put_content_key(lockbox.lockbox_id(), key))??;
                Ok(lockbox)
            }
            LockboxCreate::Password(password) => {
                let lockbox = Lockbox::create_file(path, LockboxCreate::Password(password))?;
                let unlocked = VaultUnlock::path_with_password(path, password)?;
                if let Err(err) = unlocked
                    .with_key(|key| self.store.put_content_key(unlocked.lockbox_id, key))
                    .and_then(|result| result)
                {
                    if !matches!(err, Error::Io(_)) {
                        return Err(err);
                    }
                }
                Ok(lockbox)
            }
            LockboxCreate::RecipientPublicKey(recipient) => {
                Lockbox::create_file(path, LockboxCreate::RecipientPublicKey(recipient))
            }
        }
    }

    pub fn open_lockbox(&self, path: impl AsRef<Path>) -> Result<Lockbox> {
        let path = path.as_ref();
        let lockbox_id = Lockbox::read_lockbox_id_path(path)?;
        let Some(key) = self.store.get_content_key(lockbox_id)? else {
            return Err(Error::InvalidKey);
        };
        let key = SecretVec::try_from_vec(key)?;
        Lockbox::open_file(path, LockboxUnlock::ContentKey(key))
    }

    pub fn unlock_lockbox(
        &self,
        path: impl AsRef<Path>,
        unlock: LockboxUnlock<'_>,
    ) -> Result<Lockbox> {
        let path = path.as_ref();
        match unlock {
            LockboxUnlock::ContentKey(key) => {
                let store_key = key.try_clone()?;
                let lockbox = Lockbox::open_file(path, LockboxUnlock::ContentKey(key))?;
                store_key
                    .with_bytes(|key| self.store.put_content_key(lockbox.lockbox_id(), key))??;
                Ok(lockbox)
            }
            LockboxUnlock::Password(password) => {
                let unlocked = unlock_path_or_backup_with_password(path, password)?;
                unlocked.with_key(|key| self.store.put_content_key(unlocked.lockbox_id, key))??;
                unlocked.open_path(path)
            }
            LockboxUnlock::RecipientKeyPair(recipient) => {
                let unlocked = unlock_path_or_backup_with_recipient(path, &recipient)?;
                unlocked.with_key(|key| self.store.put_content_key(unlocked.lockbox_id, key))??;
                unlocked.open_path(path)
            }
        }
    }

    pub fn lock_lockbox(&self, path: impl AsRef<Path>) -> Result<()> {
        let lockbox_id = Lockbox::read_lockbox_id_path(path.as_ref())?;
        self.store.forget_content_key(lockbox_id)
    }

    pub fn lock_all(&self) -> Result<()> {
        self.store.forget_all_content_keys()
    }
}

fn unlock_path_or_backup_with_password(
    path: &Path,
    password: &SecretString,
) -> Result<UnlockedContentKey> {
    match VaultUnlock::path_with_password(path, password) {
        Ok(unlocked) => Ok(unlocked),
        Err(primary_err) => {
            let lockbox_id =
                Lockbox::read_lockbox_id_path(path).map_err(|_| primary_err.clone())?;
            let vault_password = vault_password_from_env().map_err(|_| primary_err.clone())?;
            let backup = VaultDirectory::open_default(&vault_password)
                .and_then(|vault| vault.load_key_directory_backup(lockbox_id))
                .map_err(|_| primary_err.clone())?;
            VaultUnlock::key_directory_backup_with_password(&backup, password)
                .map_err(|_| primary_err)
        }
    }
}

fn unlock_path_or_backup_with_recipient(
    path: &Path,
    recipient: &lockbox_core::RecipientKeyPair,
) -> Result<UnlockedContentKey> {
    match VaultUnlock::path_with_recipient(path, recipient) {
        Ok(unlocked) => Ok(unlocked),
        Err(primary_err) => {
            let lockbox_id =
                Lockbox::read_lockbox_id_path(path).map_err(|_| primary_err.clone())?;
            let vault_password = vault_password_from_env().map_err(|_| primary_err.clone())?;
            let backup = VaultDirectory::open_default(&vault_password)
                .and_then(|vault| vault.load_key_directory_backup(lockbox_id))
                .map_err(|_| primary_err.clone())?;
            VaultUnlock::key_directory_backup_with_recipient(&backup, recipient)
                .map_err(|_| primary_err)
        }
    }
}

fn vault_password_from_env() -> Result<SecretString> {
    SecretString::try_from_env("LOCKBOX_VAULT_PASSWORD")?.ok_or(Error::InvalidKey)
}
