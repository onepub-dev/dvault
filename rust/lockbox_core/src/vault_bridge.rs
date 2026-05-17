//! Narrow bridge used by `lockbox_vault`.
//!
//! Normal callers should use `Lockbox::open_file`. This module exists because
//! the vault crate needs to cache an unlocked content key and recover from
//! vault-stored key-directory backups.

use std::path::Path;

use crate::{Lockbox, RecipientKeyPair, Result, SecretString};

pub use crate::lockbox::UnlockedContentKey;

/// Unlock helpers needed by the separate vault crate.
pub struct VaultUnlock;

impl VaultUnlock {
    /// Unlock the embedded key directory with a password and return the content key.
    pub fn path_with_password(path: &Path, password: &SecretString) -> Result<UnlockedContentKey> {
        Lockbox::unlock_path_with_password(path, password)
    }

    /// Unlock key-directory backup bytes with a password.
    pub fn key_directory_backup_with_password(
        bytes: &[u8],
        password: &SecretString,
    ) -> Result<UnlockedContentKey> {
        Lockbox::unlock_key_directory_backup_with_password(bytes, password)
    }

    /// Unlock the embedded key directory with a recipient keypair and return the content key.
    pub fn path_with_recipient(
        path: &Path,
        recipient: &RecipientKeyPair,
    ) -> Result<UnlockedContentKey> {
        Lockbox::unlock_path_with_recipient(path, recipient)
    }

    /// Unlock key-directory backup bytes with a recipient keypair.
    pub fn key_directory_backup_with_recipient(
        bytes: &[u8],
        recipient: &RecipientKeyPair,
    ) -> Result<UnlockedContentKey> {
        Lockbox::unlock_key_directory_backup_with_recipient(bytes, recipient)
    }
}
