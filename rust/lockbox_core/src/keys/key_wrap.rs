use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::MlKem1024;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{secret_vec::SecretVec, Error, Result};

/// ML-KEM-1024 recipient keypair.
///
/// The private key is represented by its ML-KEM decapsulation seed and stored
/// in `SecretVec`; the public recipient key is cached separately for wrapping
/// new content keys.
pub struct RecipientKeyPair {
    decapsulation_seed: SecretVec,
    encapsulation_key: ml_kem::EncapsulationKey1024,
}

/// Public ML-KEM-1024 recipient key.
///
/// This key can be shared with a lockbox creator. It can wrap a lockbox content
/// key for the holder of the matching `RecipientKeyPair`, but it cannot unlock a
/// lockbox by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientPublicKey {
    encapsulation_key: ml_kem::EncapsulationKey1024,
}

/// Content key wrapped to an ML-KEM-1024 recipient.
#[derive(Debug, Clone)]
pub struct RecipientWrappedKey {
    ciphertext: ml_kem::Ciphertext<MlKem1024>,
    encrypted_key: Vec<u8>,
}

impl RecipientKeyPair {
    /// Generate a fresh ML-KEM-1024 keypair.
    ///
    /// Returns `Error::SecurityLimitExceeded` if the private seed cannot be
    /// stored in secure memory.
    pub fn generate() -> Result<Self> {
        let (decapsulation_key, encapsulation_key) = MlKem1024::generate_keypair();
        let mut seed = decapsulation_key.to_bytes();
        let decapsulation_seed = SecretVec::try_from_slice(seed.as_ref())?;
        seed.zeroize();
        Ok(Self {
            decapsulation_seed,
            encapsulation_key,
        })
    }

    /// Encrypt a content key to this keypair's public recipient key.
    ///
    /// Returns `Error::InvalidKey` if authenticated wrapping fails.
    pub fn encrypt(&self, content_key: &[u8]) -> Result<RecipientWrappedKey> {
        self.public_key().encrypt(content_key)
    }

    /// Decrypt a content key previously encrypted for this keypair.
    ///
    /// Returns `Error::InvalidKey` if the seed or ciphertext is invalid, or
    /// `Error::SecurityLimitExceeded` if secure memory access fails.
    pub fn decrypt(&self, wrapped: &RecipientWrappedKey) -> Result<Vec<u8>> {
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
    pub fn public_key(&self) -> RecipientPublicKey {
        RecipientPublicKey {
            encapsulation_key: self.encapsulation_key.clone(),
        }
    }

    /// Construct a keypair by taking ownership of a private seed buffer.
    ///
    /// Returns `Error::InvalidKey` if the seed does not encode an ML-KEM-1024
    /// decapsulation key, or `Error::SecurityLimitExceeded` if secure memory
    /// access fails.
    pub fn from_private_seed(decapsulation_seed: SecretVec) -> Result<Self> {
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

    /// Clone the private seed into a new `SecretVec`.
    ///
    /// Returns `Error::SecurityLimitExceeded` if secure memory allocation
    /// fails.
    pub fn private_seed(&self) -> Result<SecretVec> {
        self.decapsulation_seed.try_clone().map_err(Into::into)
    }
}

impl RecipientPublicKey {
    /// Decode a public recipient key from its byte representation.
    ///
    /// Returns `Error::CorruptHeader` if the bytes do not encode an
    /// ML-KEM-1024 recipient key.
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
    ///
    /// Returns `Error::InvalidKey` if authenticated wrapping fails.
    pub fn encrypt(&self, content_key: &[u8]) -> Result<RecipientWrappedKey> {
        let (ciphertext, shared_secret) = self.encapsulation_key.encapsulate();
        let mut wrapping_key = derive_wrapping_key(shared_secret.as_ref());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrapping_key));
        let encrypted_key = cipher
            .encrypt(Nonce::from_slice(&[0u8; 12]), content_key)
            .map_err(|_| Error::InvalidKey)?;
        wrapping_key.zeroize();
        Ok(RecipientWrappedKey {
            ciphertext,
            encrypted_key,
        })
    }
}

impl RecipientWrappedKey {
    /// Reconstruct a wrapped key from serialized ciphertext components.
    ///
    /// Returns `Error::CorruptHeader` if the ciphertext bytes are not a valid
    /// ML-KEM-1024 ciphertext.
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
