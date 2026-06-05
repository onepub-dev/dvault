use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroize;

use crate::key_derivation::{derive_key_from_password, derive_key_from_password_bytes};
use crate::key_wrap::{RecipientKeyPair, RecipientPublicKey, RecipientWrappedKey};
use crate::secret_vec::SecretString;
use crate::{Error, Result};
use std::fmt;

/// Maximum UTF-8 byte length for a user-facing key slot name.
pub const MAX_KEY_SLOT_NAME_BYTES: usize = 255;

/// User-facing protection type represented by a key slot.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockboxKeySlotProtection {
    /// Password-derived wrapping key.
    Password,
    /// Public-key recipient wrapping key.
    Recipient,
}

/// Algorithm used by a key slot to wrap the lockbox content key.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockboxKeySlotAlgorithm {
    /// Argon2id password derivation plus ChaCha20-Poly1305 key wrapping.
    Argon2idChaCha20Poly1305,
    /// X25519 plus ML-KEM-768 recipient wrapping, then ChaCha20-Poly1305.
    X25519MlKem768ChaCha20Poly1305,
}

impl LockboxKeySlotAlgorithm {
    /// Stable display name for this key slot algorithm.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Argon2idChaCha20Poly1305 => "argon2id+chacha20-poly1305",
            Self::X25519MlKem768ChaCha20Poly1305 => "x25519+ml-kem-768+chacha20-poly1305",
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
    /// User-facing label for this slot, when one was supplied.
    pub name: Option<String>,
    /// User-facing protection type for this slot.
    pub protection: LockboxKeySlotProtection,
    /// Algorithm used to wrap the lockbox content key.
    ///
    /// Multiple algorithms may exist for one protection type. For example, a
    /// future release can add another recipient algorithm while still reporting
    /// `LockboxKeySlotProtection::Recipient`.
    pub algorithm: LockboxKeySlotAlgorithm,
}

#[derive(Debug, Clone)]
pub(crate) enum KeySlot {
    Password {
        id: u64,
        salt: Vec<u8>,
        encrypted_key: Vec<u8>,
    },
    HybridRecipient {
        id: u64,
        name: Option<String>,
        wrapped: Box<RecipientWrappedKey>,
    },
}

impl KeySlot {
    pub(crate) fn id(&self) -> u64 {
        match self {
            KeySlot::Password { id, .. } | KeySlot::HybridRecipient { id, .. } => *id,
        }
    }

    pub(crate) fn info(&self) -> LockboxKeySlot {
        match self {
            KeySlot::Password { id, .. } => LockboxKeySlot {
                id: *id,
                name: None,
                protection: LockboxKeySlotProtection::Password,
                algorithm: LockboxKeySlotAlgorithm::Argon2idChaCha20Poly1305,
            },
            KeySlot::HybridRecipient { id, name, .. } => LockboxKeySlot {
                id: *id,
                name: name.clone(),
                protection: LockboxKeySlotProtection::Recipient,
                algorithm: LockboxKeySlotAlgorithm::X25519MlKem768ChaCha20Poly1305,
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

    pub(crate) fn hybrid_recipient(
        id: u64,
        name: Option<String>,
        recipient: &RecipientPublicKey,
        content_key: &[u8],
    ) -> Result<Self> {
        if let Some(name) = name.as_deref() {
            validate_key_slot_name(name)?;
        }
        Ok(Self::HybridRecipient {
            id,
            name,
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

    pub(crate) fn try_recipient(&self, recipient: &RecipientKeyPair) -> Result<Vec<u8>> {
        match self {
            KeySlot::HybridRecipient { wrapped, .. } => recipient.decrypt(wrapped),
            _ => Err(Error::InvalidKey),
        }
    }
}

pub(crate) fn validate_key_slot_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidInput(
            "access name must not be empty".to_string(),
        ));
    }
    if name.len() > MAX_KEY_SLOT_NAME_BYTES {
        return Err(Error::InvalidInput(format!(
            "access name exceeds {MAX_KEY_SLOT_NAME_BYTES} bytes"
        )));
    }
    let valid_chars = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid_chars {
        return Err(Error::InvalidInput(
            "access name must contain only ASCII letters, digits, '-' or '_'".to_string(),
        ));
    }
    Ok(())
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
