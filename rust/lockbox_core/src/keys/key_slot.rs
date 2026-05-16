use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::key_derivation::{derive_key_from_password, derive_key_from_password_bytes};
use crate::key_wrap::{MlKemKeyPair, MlKemRecipientKey, MlKemWrappedKey};
use crate::secret_bytes::SecretString;
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySlotKind {
    Password,
    MlKem1024,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySlotInfo {
    pub id: u64,
    pub kind: KeySlotKind,
    pub algorithm: String,
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
        wrapped: Box<MlKemWrappedKey>,
    },
}

impl KeySlot {
    pub(crate) fn id(&self) -> u64 {
        match self {
            KeySlot::Password { id, .. } | KeySlot::MlKem1024 { id, .. } => *id,
        }
    }

    pub(crate) fn info(&self) -> KeySlotInfo {
        match self {
            KeySlot::Password { id, .. } => KeySlotInfo {
                id: *id,
                kind: KeySlotKind::Password,
                algorithm: "argon2id+chacha20-poly1305".to_string(),
            },
            KeySlot::MlKem1024 { id, .. } => KeySlotInfo {
                id: *id,
                kind: KeySlotKind::MlKem1024,
                algorithm: "ml-kem-1024+chacha20-poly1305".to_string(),
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
        recipient: &MlKemRecipientKey,
        content_key: &[u8],
    ) -> Result<Self> {
        Ok(Self::MlKem1024 {
            id,
            wrapped: Box::new(recipient.wrap_key(content_key)?),
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

    pub(crate) fn try_ml_kem(&self, recipient: &MlKemKeyPair) -> Result<Vec<u8>> {
        match self {
            KeySlot::MlKem1024 { wrapped, .. } => recipient.unwrap_key(wrapped),
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

pub(crate) fn slot_fingerprint(data: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[0..8].try_into().unwrap())
}
