use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::MlKem1024;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{Error, Result};

pub struct MlKemKeyPair {
    decapsulation_key: ml_kem::DecapsulationKey1024,
    encapsulation_key: ml_kem::EncapsulationKey1024,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemRecipientKey {
    encapsulation_key: ml_kem::EncapsulationKey1024,
}

#[derive(Debug, Clone)]
pub struct MlKemWrappedKey {
    ciphertext: ml_kem::Ciphertext<MlKem1024>,
    encrypted_key: Vec<u8>,
}

impl MlKemKeyPair {
    pub fn generate() -> Self {
        let (decapsulation_key, encapsulation_key) = MlKem1024::generate_keypair();
        Self {
            decapsulation_key,
            encapsulation_key,
        }
    }

    pub fn wrap_key(&self, vault_key: &[u8]) -> Result<MlKemWrappedKey> {
        self.recipient_key().wrap_key(vault_key)
    }

    pub fn unwrap_key(&self, wrapped: &MlKemWrappedKey) -> Result<Vec<u8>> {
        let shared_secret = self.decapsulation_key.decapsulate(&wrapped.ciphertext);
        let mut wrapping_key = derive_wrapping_key(shared_secret.as_ref());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrapping_key));
        let key = cipher
            .decrypt(
                Nonce::from_slice(&[0u8; 12]),
                wrapped.encrypted_key.as_ref(),
            )
            .map_err(|_| Error::InvalidKey);
        wrapping_key.zeroize();
        key
    }

    pub fn recipient_key(&self) -> MlKemRecipientKey {
        MlKemRecipientKey {
            encapsulation_key: self.encapsulation_key.clone(),
        }
    }

    pub fn from_seed_bytes(bytes: &[u8]) -> Result<Self> {
        let seed = ml_kem::Seed::try_from(bytes).map_err(|_| Error::InvalidKey)?;
        let decapsulation_key = ml_kem::DecapsulationKey1024::from_seed(seed);
        let encapsulation_key = decapsulation_key.encapsulation_key().clone();
        Ok(Self {
            decapsulation_key,
            encapsulation_key,
        })
    }

    pub fn to_seed_bytes(&self) -> Vec<u8> {
        self.decapsulation_key.to_bytes().to_vec()
    }
}

impl MlKemRecipientKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key = ml_kem::kem::Key::<ml_kem::EncapsulationKey1024>::try_from(bytes)
            .map_err(|_| Error::CorruptHeader)?;
        let encapsulation_key =
            ml_kem::EncapsulationKey1024::new(&key).map_err(|_| Error::CorruptHeader)?;
        Ok(Self { encapsulation_key })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.encapsulation_key.to_bytes().to_vec()
    }

    pub fn wrap_key(&self, vault_key: &[u8]) -> Result<MlKemWrappedKey> {
        let (ciphertext, shared_secret) = self.encapsulation_key.encapsulate();
        let mut wrapping_key = derive_wrapping_key(shared_secret.as_ref());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrapping_key));
        let encrypted_key = cipher
            .encrypt(Nonce::from_slice(&[0u8; 12]), vault_key)
            .map_err(|_| Error::InvalidKey)?;
        wrapping_key.zeroize();
        Ok(MlKemWrappedKey {
            ciphertext,
            encrypted_key,
        })
    }
}

impl MlKemWrappedKey {
    pub fn from_parts(ciphertext: Vec<u8>, encrypted_key: Vec<u8>) -> Result<Self> {
        let ciphertext = ml_kem::Ciphertext::<MlKem1024>::try_from(ciphertext.as_slice())
            .map_err(|_| Error::CorruptHeader)?;
        Ok(Self {
            ciphertext,
            encrypted_key,
        })
    }

    pub fn ciphertext_bytes(&self) -> &[u8] {
        self.ciphertext.as_ref()
    }

    pub fn encrypted_key(&self) -> &[u8] {
        &self.encrypted_key
    }
}

fn derive_wrapping_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"lockbox-v2-ml-kem-1024-wrap-key");
    hasher.update(shared_secret);
    hasher.finalize().into()
}
