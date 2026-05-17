use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroize;

use crate::key_derivation::{derive_key_from_password, derive_key_from_password_bytes};
use crate::key_wrap::{RecipientKeyPair, RecipientPublicKey, RecipientWrappedKey};
use crate::secret_vec::SecretString;
use crate::{Error, Result};
use std::fmt;

/// Type of key slot that can unlock a lockbox content key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockboxKeySlotKind {
    /// Password-derived wrapping key.
    Password,
    /// Public-key recipient wrapping key.
    Recipient,
}

/// Algorithm used by a key slot to wrap the lockbox content key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockboxKeySlotAlgorithm {
    /// Argon2id password derivation plus ChaCha20-Poly1305 key wrapping.
    Argon2idChaCha20Poly1305,
    /// ML-KEM-1024 recipient encapsulation plus ChaCha20-Poly1305 key wrapping.
    MlKem1024ChaCha20Poly1305,
}

impl LockboxKeySlotAlgorithm {
    /// Stable display name for this key slot algorithm.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Argon2idChaCha20Poly1305 => "argon2id+chacha20-poly1305",
            Self::MlKem1024ChaCha20Poly1305 => "ml-kem-1024+chacha20-poly1305",
        }
    }
}

impl fmt::Display for LockboxKeySlotAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Public metadata for one key slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockboxKeySlot {
    /// Stable slot id used for deletion.
    pub id: u64,
    /// Slot type.
    pub kind: LockboxKeySlotKind,
    /// Algorithm used to wrap the lockbox content key.
    pub algorithm: LockboxKeySlotAlgorithm,
}

#[derive(Debug, Clone)]
pub(crate) enum KeySlot {
    Password {
        id: u64,
        salt: Vec<u8>,
        encrypted_key: Vec<u8>,
    },
    MlKem1024 {
        id: u64,
        wrapped: Box<RecipientWrappedKey>,
    },
}

impl KeySlot {
    pub(crate) fn id(&self) -> u64 {
        match self {
            KeySlot::Password { id, .. } | KeySlot::MlKem1024 { id, .. } => *id,
        }
    }

    pub(crate) fn info(&self) -> LockboxKeySlot {
        match self {
            KeySlot::Password { id, .. } => LockboxKeySlot {
                id: *id,
                kind: LockboxKeySlotKind::Password,
                algorithm: LockboxKeySlotAlgorithm::Argon2idChaCha20Poly1305,
            },
            KeySlot::MlKem1024 { id, .. } => LockboxKeySlot {
                id: *id,
                kind: LockboxKeySlotKind::Recipient,
                algorithm: LockboxKeySlotAlgorithm::MlKem1024ChaCha20Poly1305,
            },
        }
    }

    pub(crate) fn password_bytes(
        id: u64,
        password: &[u8],
        salt: Vec<u8>,
        content_key: &[u8],
    ) -> Result<Self> {
        let mut wrapping_key = derive_key_from_password_bytes(password, &salt)?;
        let encrypted_key = encrypt_wrapped_key(&wrapping_key, content_key)?;
        wrapping_key.zeroize();
        Ok(Self::Password {
            id,
            salt,
            encrypted_key,
        })
    }

    pub(crate) fn ml_kem_1024(
        id: u64,
        recipient: &RecipientPublicKey,
        content_key: &[u8],
    ) -> Result<Self> {
        Ok(Self::MlKem1024 {
            id,
            wrapped: Box::new(recipient.encrypt(content_key)?),
        })
    }

    pub(crate) fn try_password(&self, password: &SecretString) -> Result<Vec<u8>> {
        match self {
            KeySlot::Password {
                salt,
                encrypted_key,
                ..
            } => {
                let mut wrapping_key = derive_key_from_password(password, salt)?;
                let key = decrypt_wrapped_key(&wrapping_key, encrypted_key);
                wrapping_key.zeroize();
                key
            }
            _ => Err(Error::InvalidKey),
        }
    }

    pub(crate) fn try_ml_kem(&self, recipient: &RecipientKeyPair) -> Result<Vec<u8>> {
        match self {
            KeySlot::MlKem1024 { wrapped, .. } => recipient.decrypt(wrapped),
            _ => Err(Error::InvalidKey),
        }
    }
}

pub(crate) fn encrypt_wrapped_key(wrapping_key: &[u8; 32], content_key: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(wrapping_key));
    cipher
        .encrypt(Nonce::from_slice(&[0u8; 12]), content_key)
        .map_err(|_| Error::InvalidKey)
}

pub(crate) fn decrypt_wrapped_key(
    wrapping_key: &[u8; 32],
    encrypted_key: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(wrapping_key));
    cipher
        .decrypt(Nonce::from_slice(&[0u8; 12]), encrypted_key)
        .map_err(|_| Error::InvalidKey)
}

pub(crate) fn next_key_slot_id(slots: &[KeySlot]) -> u64 {
    slots.iter().map(KeySlot::id).max().unwrap_or(0) + 1
}

pub(crate) fn random_content_key() -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|err| Error::Io(err.to_string()))?;
    Ok(key)
}

pub(crate) fn random_salt() -> Result<Vec<u8>> {
    let mut salt = vec![0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|err| Error::Io(err.to_string()))?;
    Ok(salt)
}
