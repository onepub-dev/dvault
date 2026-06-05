use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::MlKem768;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::Zeroize;

use crate::{secret_vec::SecretVec, Error, Result};

const PUBLIC_MAGIC: &[u8; 8] = b"LBX2HPUB";
const PRIVATE_MAGIC: &[u8; 8] = b"LBX2HPRV";
const HYBRID_KEY_VERSION: u16 = 1;
const HYBRID_ALGORITHM_X25519_MLKEM768: u16 = 1;
const X25519_KEY_LEN: usize = 32;

/// Hybrid X25519 + ML-KEM-768 recipient keypair.
///
/// The private material is stored as a versioned Lockbox binary record in
/// `SecretVec`. The public recipient key is cached separately for wrapping new
/// content keys.
pub struct RecipientKeyPair {
    private_key_bytes: SecretVec,
    x25519_public_key: [u8; X25519_KEY_LEN],
    mlkem_encapsulation_key: ml_kem::EncapsulationKey768,
}

/// Public hybrid X25519 + ML-KEM-768 recipient key.
///
/// This key can be shared with a lockbox creator. It can wrap a lockbox content
/// key for the holder of the matching `RecipientKeyPair`, but it cannot unlock a
/// lockbox by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientPublicKey {
    x25519_public_key: [u8; X25519_KEY_LEN],
    mlkem_encapsulation_key: ml_kem::EncapsulationKey768,
}

/// Content key wrapped to a hybrid X25519 + ML-KEM-768 recipient.
#[derive(Debug, Clone)]
pub struct RecipientWrappedKey {
    x25519_ephemeral_public_key: [u8; X25519_KEY_LEN],
    mlkem_ciphertext: ml_kem::Ciphertext<MlKem768>,
    encrypted_key: Vec<u8>,
}

impl RecipientKeyPair {
    /// Generate a fresh hybrid X25519 + ML-KEM-768 keypair.
    ///
    /// Returns `Error::SecurityLimitExceeded` if the private record cannot be
    /// stored in secure memory.
    pub fn generate() -> Result<Self> {
        let mut x25519_secret_bytes = [0_u8; X25519_KEY_LEN];
        getrandom::getrandom(&mut x25519_secret_bytes).map_err(|err| Error::Io(err.to_string()))?;
        let x25519_secret_key = X25519SecretKey::from(x25519_secret_bytes);
        let x25519_public_key = X25519PublicKey::from(&x25519_secret_key).to_bytes();
        x25519_secret_bytes.zeroize();

        let (mlkem_decapsulation_key, mlkem_encapsulation_key) = MlKem768::generate_keypair();
        let mut mlkem_seed = mlkem_decapsulation_key.to_bytes();
        let private_key_bytes =
            encode_private_key(&x25519_secret_key.to_bytes(), mlkem_seed.as_ref())?;
        mlkem_seed.zeroize();

        Ok(Self {
            private_key_bytes,
            x25519_public_key,
            mlkem_encapsulation_key,
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
    /// Returns `Error::InvalidKey` if authenticated decrypt fails,
    /// `Error::InvalidKeyMaterial` if the stored private key cannot be decoded,
    /// or `Error::SecurityLimitExceeded` if secure memory access fails.
    pub fn decrypt(&self, wrapped: &RecipientWrappedKey) -> Result<Vec<u8>> {
        self.private_key_bytes.with_bytes(|bytes| {
            let decoded = decode_private_key(bytes)?;
            let x25519_secret_key = X25519SecretKey::from(decoded.x25519_secret_key);
            let peer = X25519PublicKey::from(wrapped.x25519_ephemeral_public_key);
            let x25519_secret = x25519_secret_key.diffie_hellman(&peer);

            let seed = ml_kem::Seed::try_from(decoded.mlkem_seed.as_slice()).map_err(|_| {
                Error::InvalidKeyMaterial("ML-KEM private seed has the wrong length".to_string())
            })?;
            let mlkem_decapsulation_key = ml_kem::DecapsulationKey768::from_seed(seed);
            let mlkem_secret = mlkem_decapsulation_key.decapsulate(&wrapped.mlkem_ciphertext);

            let mut wrapping_key =
                derive_wrapping_key(x25519_secret.as_bytes(), mlkem_secret.as_ref())?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrapping_key));
            let key = cipher
                .decrypt(
                    Nonce::from_slice(&[0_u8; 12]),
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
            x25519_public_key: self.x25519_public_key,
            mlkem_encapsulation_key: self.mlkem_encapsulation_key.clone(),
        }
    }

    /// Construct a keypair by taking ownership of a private key record buffer.
    ///
    /// Returns `Error::InvalidKeyMaterial` if the bytes do not encode a
    /// supported Lockbox hybrid recipient private key, or
    /// `Error::SecurityLimitExceeded` if secure memory access fails.
    pub fn from_private_key_record(private_key_bytes: SecretVec) -> Result<Self> {
        let (x25519_public_key, mlkem_encapsulation_key) =
            private_key_bytes.with_bytes(|bytes| {
                let decoded = decode_private_key(bytes)?;
                let x25519_secret_key = X25519SecretKey::from(decoded.x25519_secret_key);
                let x25519_public_key = X25519PublicKey::from(&x25519_secret_key).to_bytes();
                let seed = ml_kem::Seed::try_from(decoded.mlkem_seed.as_slice()).map_err(|_| {
                    Error::InvalidKeyMaterial(
                        "ML-KEM private seed has the wrong length".to_string(),
                    )
                })?;
                let mlkem_decapsulation_key = ml_kem::DecapsulationKey768::from_seed(seed);
                Ok::<_, Error>((
                    x25519_public_key,
                    mlkem_decapsulation_key.encapsulation_key().clone(),
                ))
            })??;
        Ok(Self {
            private_key_bytes,
            x25519_public_key,
            mlkem_encapsulation_key,
        })
    }

    /// Clone the private key record into a new `SecretVec`.
    ///
    /// Returns `Error::SecurityLimitExceeded` if secure memory allocation
    /// fails.
    pub fn private_key_record(&self) -> Result<SecretVec> {
        self.private_key_bytes.try_clone().map_err(Into::into)
    }
}

impl RecipientPublicKey {
    /// Decode a public recipient key from its versioned Lockbox byte
    /// representation.
    ///
    /// Returns `Error::InvalidKeyMaterial` if the bytes do not encode a
    /// supported hybrid recipient public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        decode_public_key(bytes)
    }

    /// Encode this public recipient key as versioned Lockbox bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_public_key(self)
    }

    /// Wrap a content key for this recipient.
    ///
    /// Returns `Error::InvalidKey` if authenticated wrapping fails.
    pub fn encrypt(&self, content_key: &[u8]) -> Result<RecipientWrappedKey> {
        let mut ephemeral_secret_bytes = [0_u8; X25519_KEY_LEN];
        getrandom::getrandom(&mut ephemeral_secret_bytes)
            .map_err(|err| Error::Io(err.to_string()))?;
        let ephemeral_secret = X25519SecretKey::from(ephemeral_secret_bytes);
        ephemeral_secret_bytes.zeroize();
        let x25519_ephemeral_public_key = X25519PublicKey::from(&ephemeral_secret).to_bytes();
        let peer = X25519PublicKey::from(self.x25519_public_key);
        let x25519_secret = ephemeral_secret.diffie_hellman(&peer);

        let (mlkem_ciphertext, mlkem_secret) = self.mlkem_encapsulation_key.encapsulate();

        let mut wrapping_key =
            derive_wrapping_key(x25519_secret.as_bytes(), mlkem_secret.as_ref())?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrapping_key));
        let encrypted_key = cipher
            .encrypt(Nonce::from_slice(&[0_u8; 12]), content_key)
            .map_err(|_| Error::InvalidKey)?;
        wrapping_key.zeroize();
        Ok(RecipientWrappedKey {
            x25519_ephemeral_public_key,
            mlkem_ciphertext,
            encrypted_key,
        })
    }
}

impl RecipientWrappedKey {
    /// Reconstruct a wrapped key from serialized hybrid ciphertext components.
    ///
    /// Returns `Error::InvalidKeyMaterial` if the component bytes are invalid.
    pub fn from_parts(
        x25519_ephemeral_public_key: Vec<u8>,
        mlkem_ciphertext: Vec<u8>,
        encrypted_key: Vec<u8>,
    ) -> Result<Self> {
        if x25519_ephemeral_public_key.len() != X25519_KEY_LEN {
            return Err(Error::InvalidKeyMaterial(
                "X25519 public key bytes have the wrong length".to_string(),
            ));
        }
        let mut x25519_public = [0_u8; X25519_KEY_LEN];
        x25519_public.copy_from_slice(&x25519_ephemeral_public_key);
        let mlkem_ciphertext = ml_kem::Ciphertext::<MlKem768>::try_from(
            mlkem_ciphertext.as_slice(),
        )
        .map_err(|_| {
            Error::InvalidKeyMaterial("ML-KEM ciphertext bytes have the wrong length".to_string())
        })?;
        Ok(Self {
            x25519_ephemeral_public_key: x25519_public,
            mlkem_ciphertext,
            encrypted_key,
        })
    }

    /// Return the ephemeral X25519 public key bytes.
    pub fn x25519_ephemeral_public_key(&self) -> &[u8; X25519_KEY_LEN] {
        &self.x25519_ephemeral_public_key
    }

    /// Return the ML-KEM ciphertext bytes.
    pub fn ciphertext_bytes(&self) -> &[u8] {
        self.mlkem_ciphertext.as_ref()
    }

    /// Return the encrypted content-key bytes.
    pub fn encrypted_key(&self) -> &[u8] {
        &self.encrypted_key
    }
}

struct DecodedPrivateKey {
    x25519_secret_key: [u8; X25519_KEY_LEN],
    mlkem_seed: Vec<u8>,
}

fn encode_public_key(key: &RecipientPublicKey) -> Vec<u8> {
    let mlkem_public = key.mlkem_encapsulation_key.to_bytes();
    let mut out = Vec::with_capacity(16 + X25519_KEY_LEN + 4 + mlkem_public.len());
    out.extend_from_slice(PUBLIC_MAGIC);
    put_u16(&mut out, HYBRID_KEY_VERSION);
    put_u16(&mut out, HYBRID_ALGORITHM_X25519_MLKEM768);
    out.extend_from_slice(&key.x25519_public_key);
    put_bytes(&mut out, mlkem_public.as_ref());
    out
}

fn decode_public_key(bytes: &[u8]) -> Result<RecipientPublicKey> {
    let mut reader = Reader::new(bytes);
    reader.magic(PUBLIC_MAGIC)?;
    reader.version()?;
    reader.algorithm()?;
    let x25519_public = reader.x25519_key()?;
    let mlkem_public = reader.bytes()?;
    reader.done()?;
    let key = ml_kem::kem::Key::<ml_kem::EncapsulationKey768>::try_from(mlkem_public.as_slice())
        .map_err(|_| {
            Error::InvalidKeyMaterial("ML-KEM public key bytes have the wrong length".to_string())
        })?;
    let mlkem_encapsulation_key = ml_kem::EncapsulationKey768::new(&key).map_err(|_| {
        Error::InvalidKeyMaterial("ML-KEM public key bytes are invalid".to_string())
    })?;
    Ok(RecipientPublicKey {
        x25519_public_key: x25519_public,
        mlkem_encapsulation_key,
    })
}

fn encode_private_key(
    x25519_secret: &[u8; X25519_KEY_LEN],
    mlkem_seed: &[u8],
) -> Result<SecretVec> {
    let mut out = SecretVec::new();
    out.try_extend_from_slice(PRIVATE_MAGIC)?;
    out.try_extend_from_slice(&HYBRID_KEY_VERSION.to_le_bytes())?;
    out.try_extend_from_slice(&HYBRID_ALGORITHM_X25519_MLKEM768.to_le_bytes())?;
    out.try_extend_from_slice(x25519_secret)?;
    out.try_extend_from_slice(&(mlkem_seed.len() as u32).to_le_bytes())?;
    out.try_extend_from_slice(mlkem_seed)?;
    Ok(out)
}

fn decode_private_key(bytes: &[u8]) -> Result<DecodedPrivateKey> {
    let mut reader = Reader::new(bytes);
    reader.magic(PRIVATE_MAGIC)?;
    reader.version()?;
    reader.algorithm()?;
    let x25519_secret_key = reader.x25519_key()?;
    let mlkem_seed = reader.bytes()?;
    reader.done()?;
    Ok(DecodedPrivateKey {
        x25519_secret_key,
        mlkem_seed,
    })
}

fn derive_wrapping_key(x25519_secret: &[u8], mlkem_secret: &[u8]) -> Result<[u8; 32]> {
    let mut input = Vec::with_capacity(4 + x25519_secret.len() + 4 + mlkem_secret.len());
    put_bytes(&mut input, x25519_secret);
    put_bytes(&mut input, mlkem_secret);
    let hkdf = Hkdf::<Sha256>::new(Some(b"lockbox-v2-hybrid-recipient-wrap"), &input);
    let mut out = [0_u8; 32];
    hkdf.expand(b"x25519-mlkem768-chacha20poly1305", &mut out)
        .map_err(|_| {
            Error::InvalidKeyMaterial("hybrid wrapping key derivation failed".to_string())
        })?;
    input.zeroize();
    Ok(out)
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn magic(&mut self, expected: &[u8]) -> Result<()> {
        if self.bytes.get(self.offset..self.offset + expected.len()) != Some(expected) {
            return Err(Error::InvalidKeyMaterial(
                "recipient key has invalid magic".to_string(),
            ));
        }
        self.offset += expected.len();
        Ok(())
    }

    fn version(&mut self) -> Result<()> {
        let version = self.u16()?;
        if version != HYBRID_KEY_VERSION {
            return Err(Error::InvalidKeyMaterial(format!(
                "recipient key version {version} is not supported"
            )));
        }
        Ok(())
    }

    fn algorithm(&mut self) -> Result<()> {
        let algorithm = self.u16()?;
        if algorithm != HYBRID_ALGORITHM_X25519_MLKEM768 {
            return Err(Error::InvalidKeyMaterial(format!(
                "recipient key algorithm {algorithm} is not supported"
            )));
        }
        Ok(())
    }

    fn u16(&mut self) -> Result<u16> {
        if self.offset + 2 > self.bytes.len() {
            return Err(Error::InvalidKeyMaterial(
                "recipient key is truncated".to_string(),
            ));
        }
        let value = u16::from_le_bytes([self.bytes[self.offset], self.bytes[self.offset + 1]]);
        self.offset += 2;
        Ok(value)
    }

    fn x25519_key(&mut self) -> Result<[u8; X25519_KEY_LEN]> {
        if self.offset + X25519_KEY_LEN > self.bytes.len() {
            return Err(Error::InvalidKeyMaterial(
                "recipient key is missing X25519 material".to_string(),
            ));
        }
        let mut out = [0_u8; X25519_KEY_LEN];
        out.copy_from_slice(&self.bytes[self.offset..self.offset + X25519_KEY_LEN]);
        self.offset += X25519_KEY_LEN;
        Ok(out)
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        if self.offset + 4 > self.bytes.len() {
            return Err(Error::InvalidKeyMaterial(
                "recipient key is truncated".to_string(),
            ));
        }
        let len = u32::from_le_bytes(self.bytes[self.offset..self.offset + 4].try_into().unwrap())
            as usize;
        self.offset += 4;
        if self.offset + len > self.bytes.len() {
            return Err(Error::InvalidKeyMaterial(
                "recipient key field is truncated".to_string(),
            ));
        }
        let out = self.bytes[self.offset..self.offset + len].to_vec();
        self.offset += len;
        Ok(out)
    }

    fn done(&self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(Error::InvalidKeyMaterial(
                "recipient key contains trailing bytes".to_string(),
            ));
        }
        Ok(())
    }
}
