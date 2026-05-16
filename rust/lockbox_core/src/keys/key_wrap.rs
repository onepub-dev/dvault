use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::MlKem1024;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{secret_vec::SecretVec, Error, Result};

/// ML-KEM-1024 private recipient keypair.
///
/// The decapsulation seed is stored in `SecretVec`; the public recipient key is
/// cached separately for wrapping new content keys.
pub struct MlKemKeyPair {
    decapsulation_seed: SecretVec,
    encapsulation_key: ml_kem::EncapsulationKey1024,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Public ML-KEM-1024 recipient key.
pub struct MlKemRecipientKey {
    encapsulation_key: ml_kem::EncapsulationKey1024,
}

#[derive(Debug, Clone)]
/// Content key wrapped to an ML-KEM-1024 recipient.
pub struct MlKemWrappedKey {
    ciphertext: ml_kem::Ciphertext<MlKem1024>,
    encrypted_key: Vec<u8>,
}

impl MlKemKeyPair {
    /// Generate a fresh ML-KEM-1024 keypair.
    pub fn generate() -> Result<Self> {
        let (decapsulation_key, encapsulation_key) = MlKem1024::generate_keypair();
        let decapsulation_seed = SecretVec::try_from_vec(decapsulation_key.to_bytes().to_vec())?;
        Ok(Self {
            decapsulation_seed,
            encapsulation_key,
        })
    }

    /// Wrap a content key to this keypair's public recipient key.
    pub fn wrap_key(&self, content_key: &[u8]) -> Result<MlKemWrappedKey> {
        self.recipient_key().wrap_key(content_key)
    }

    /// Unwrap a content key previously wrapped for this keypair.
    pub fn unwrap_key(&self, wrapped: &MlKemWrappedKey) -> Result<Vec<u8>> {
        self.decapsulation_seed.with_bytes(|seed_bytes| {
            let seed = ml_kem::Seed::try_from(seed_bytes).map_err(|_| Error::InvalidKey)?;
            let decapsulation_key = ml_kem::DecapsulationKey1024::from_seed(seed);
            let shared_secret = decapsulation_key.decapsulate(&wrapped.ciphertext);
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
        })?
    }

    /// Return the public recipient key for this keypair.
    pub fn recipient_key(&self) -> MlKemRecipientKey {
        MlKemRecipientKey {
            encapsulation_key: self.encapsulation_key.clone(),
        }
    }

    /// Construct a keypair from raw seed bytes.
    pub fn from_seed_bytes(bytes: &[u8]) -> Result<Self> {
        let seed = ml_kem::Seed::try_from(bytes).map_err(|_| Error::InvalidKey)?;
        let decapsulation_key = ml_kem::DecapsulationKey1024::from_seed(seed);
        let encapsulation_key = decapsulation_key.encapsulation_key().clone();
        let decapsulation_seed = SecretVec::try_from_slice(bytes)?;
        Ok(Self {
            decapsulation_seed,
            encapsulation_key,
        })
    }

    /// Construct a keypair by taking ownership of a secure seed buffer.
    pub fn from_seed_secure(decapsulation_seed: SecretVec) -> Result<Self> {
        let encapsulation_key = decapsulation_seed.with_bytes(|bytes| {
            let seed = ml_kem::Seed::try_from(bytes).map_err(|_| Error::InvalidKey)?;
            let decapsulation_key = ml_kem::DecapsulationKey1024::from_seed(seed);
            Ok::<_, Error>(decapsulation_key.encapsulation_key().clone())
        })??;
        Ok(Self {
            decapsulation_seed,
            encapsulation_key,
        })
    }

    /// Temporarily expose the private seed inside a secure read scope.
    pub fn with_seed_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        Ok(self.decapsulation_seed.with_bytes(f)?)
    }

    /// Clone the private seed into a new secure buffer.
    pub fn to_seed_secure(&self) -> Result<SecretVec> {
        self.decapsulation_seed.try_clone().map_err(Into::into)
    }

    /// Clone the private seed into ordinary memory.
    ///
    /// Prefer `to_seed_secure()` unless the caller is explicitly exporting or
    /// testing private-key material.
    pub fn to_seed_bytes(&self) -> Result<Vec<u8>> {
        self.with_seed_bytes(|bytes| bytes.to_vec())
    }
}

impl MlKemRecipientKey {
    /// Decode a public recipient key from its byte representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key = ml_kem::kem::Key::<ml_kem::EncapsulationKey1024>::try_from(bytes)
            .map_err(|_| Error::CorruptHeader)?;
        let encapsulation_key =
            ml_kem::EncapsulationKey1024::new(&key).map_err(|_| Error::CorruptHeader)?;
        Ok(Self { encapsulation_key })
    }

    /// Encode this public recipient key as bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encapsulation_key.to_bytes().to_vec()
    }

    /// Wrap a content key for this recipient.
    pub fn wrap_key(&self, content_key: &[u8]) -> Result<MlKemWrappedKey> {
        let (ciphertext, shared_secret) = self.encapsulation_key.encapsulate();
        let mut wrapping_key = derive_wrapping_key(shared_secret.as_ref());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrapping_key));
        let encrypted_key = cipher
            .encrypt(Nonce::from_slice(&[0u8; 12]), content_key)
            .map_err(|_| Error::InvalidKey)?;
        wrapping_key.zeroize();
        Ok(MlKemWrappedKey {
            ciphertext,
            encrypted_key,
        })
    }
}

impl MlKemWrappedKey {
    /// Reconstruct a wrapped key from serialized ciphertext components.
    pub fn from_parts(ciphertext: Vec<u8>, encrypted_key: Vec<u8>) -> Result<Self> {
        let ciphertext = ml_kem::Ciphertext::<MlKem1024>::try_from(ciphertext.as_slice())
            .map_err(|_| Error::CorruptHeader)?;
        Ok(Self {
            ciphertext,
            encrypted_key,
        })
    }

    /// Return the ML-KEM ciphertext bytes.
    pub fn ciphertext_bytes(&self) -> &[u8] {
        self.ciphertext.as_ref()
    }

    /// Return the encrypted content-key bytes.
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
