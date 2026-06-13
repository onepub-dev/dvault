use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    Verifier as Ed25519Verifier, VerifyingKey as Ed25519VerifyingKey,
};
use ml_dsa::{
    Keypair, MlDsa65, Signature as MlDsaSignature, SignatureEncoding, Signer as MlDsaSigner,
    SigningKey as MlDsaSigningKey, Verifier as MlDsaVerifier, VerifyingKey as MlDsaVerifyingKey,
};
use std::fmt;

use crate::commit_auth::{
    CommitSignature, SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ALGORITHM_ML_DSA_65,
};
use crate::secret_vec::SecretVec;
use crate::{Error, Result};

const SIGNING_PUBLIC_MAGIC: &[u8; 8] = b"LBX2SPUB";
const SIGNING_PRIVATE_MAGIC: &[u8; 8] = b"LBX2SPRV";
const SIGNING_KEY_VERSION: u16 = 1;
const SIGNING_ALGORITHM_ED25519_MLDSA65: u16 = 1;
const ED25519_SEED_LEN: usize = 32;
const ML_DSA_SEED_LEN: usize = 32;

pub struct OwnerSigningKeyPair {
    private_key_bytes: SecretVec,
    public_key: OwnerSigningPublicKey,
    ed25519: Ed25519SigningKey,
    ml_dsa65: MlDsaSigningKey<MlDsa65>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerSigningPublicKey {
    ed25519_public_key: [u8; 32],
    ml_dsa65_public_key: Vec<u8>,
}

impl OwnerSigningKeyPair {
    pub fn generate() -> Result<Self> {
        let mut ed25519_seed = [0_u8; ED25519_SEED_LEN];
        let mut ml_dsa65_seed = [0_u8; ML_DSA_SEED_LEN];
        getrandom::getrandom(&mut ed25519_seed).map_err(|err| Error::Io(err.to_string()))?;
        getrandom::getrandom(&mut ml_dsa65_seed).map_err(|err| Error::Io(err.to_string()))?;
        Self::from_seeds(ed25519_seed, ml_dsa65_seed)
    }

    pub fn from_private_key_record(private_key_bytes: SecretVec) -> Result<Self> {
        let (ed25519_seed, ml_dsa65_seed) =
            private_key_bytes.with_bytes(decode_private_key_record)??;
        let mut keypair = Self::from_seeds(ed25519_seed, ml_dsa65_seed)?;
        keypair.private_key_bytes = private_key_bytes;
        Ok(keypair)
    }

    pub fn private_key_record(&self) -> Result<SecretVec> {
        self.private_key_bytes.try_clone().map_err(Into::into)
    }

    pub fn public_key(&self) -> OwnerSigningPublicKey {
        self.public_key.clone()
    }

    pub(crate) fn try_clone(&self) -> Result<Self> {
        Self::from_private_key_record(self.private_key_record()?)
    }

    fn from_seeds(
        ed25519_seed: [u8; ED25519_SEED_LEN],
        ml_dsa65_seed: [u8; ML_DSA_SEED_LEN],
    ) -> Result<Self> {
        let ed25519 = Ed25519SigningKey::from_bytes(&ed25519_seed);
        let ml_dsa65_seed = ml_dsa::Seed::from(ml_dsa65_seed);
        let ml_dsa65 = MlDsaSigningKey::<MlDsa65>::from_seed(&ml_dsa65_seed);
        let public_key = OwnerSigningPublicKey {
            ed25519_public_key: ed25519.verifying_key().to_bytes(),
            ml_dsa65_public_key: ml_dsa65.verifying_key().encode().to_vec(),
        };
        let private_key_bytes = encode_private_key_record(&ed25519_seed, ml_dsa65_seed.as_ref())?;
        Ok(Self {
            private_key_bytes,
            public_key,
            ed25519,
            ml_dsa65,
        })
    }

    pub(crate) fn empty_signatures(&self) -> Vec<CommitSignature> {
        vec![
            CommitSignature {
                algorithm: SIGNATURE_ALGORITHM_ED25519,
                public_key: self.public_key.ed25519_public_key.to_vec(),
                signature: Vec::new(),
            },
            CommitSignature {
                algorithm: SIGNATURE_ALGORITHM_ML_DSA_65,
                public_key: self.public_key.ml_dsa65_public_key.clone(),
                signature: Vec::new(),
            },
        ]
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Vec<CommitSignature> {
        let ed25519_signature = self.ed25519.sign(message);
        let ml_dsa65_signature = self.ml_dsa65.sign(message);
        vec![
            CommitSignature {
                algorithm: SIGNATURE_ALGORITHM_ED25519,
                public_key: self.public_key.ed25519_public_key.to_vec(),
                signature: ed25519_signature.to_bytes().to_vec(),
            },
            CommitSignature {
                algorithm: SIGNATURE_ALGORITHM_ML_DSA_65,
                public_key: self.public_key.ml_dsa65_public_key.clone(),
                signature: ml_dsa65_signature.to_bytes().to_vec(),
            },
        ]
    }
}

impl fmt::Debug for OwnerSigningKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerSigningKeyPair")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl OwnerSigningPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        decode_public_key(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        encode_public_key(self)
    }
}

pub(crate) fn verify_commit_signatures(
    message: &[u8],
    signatures: &[CommitSignature],
) -> Result<()> {
    let mut saw_ed25519 = false;
    let mut saw_ml_dsa65 = false;
    for signature in signatures {
        match signature.algorithm {
            SIGNATURE_ALGORITHM_ED25519 => {
                let public_key = Ed25519VerifyingKey::from_bytes(
                    signature
                        .public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::CorruptRecord)?,
                )
                .map_err(|_| Error::CorruptRecord)?;
                let signature = Ed25519Signature::from_slice(&signature.signature)
                    .map_err(|_| Error::CorruptRecord)?;
                public_key
                    .verify(message, &signature)
                    .map_err(|_| Error::CorruptRecord)?;
                saw_ed25519 = true;
            }
            SIGNATURE_ALGORITHM_ML_DSA_65 => {
                let public_key = MlDsaVerifyingKey::<MlDsa65>::decode(
                    &signature
                        .public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::CorruptRecord)?,
                );
                let signature = MlDsaSignature::<MlDsa65>::try_from(signature.signature.as_slice())
                    .map_err(|_| Error::CorruptRecord)?;
                public_key
                    .verify(message, &signature)
                    .map_err(|_| Error::CorruptRecord)?;
                saw_ml_dsa65 = true;
            }
            _ => return Err(Error::CorruptRecord),
        }
    }
    if saw_ed25519 && saw_ml_dsa65 {
        Ok(())
    } else {
        Err(Error::CorruptRecord)
    }
}

fn encode_public_key(key: &OwnerSigningPublicKey) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SIGNING_PUBLIC_MAGIC);
    put_u16(&mut out, SIGNING_KEY_VERSION);
    put_u16(&mut out, SIGNING_ALGORITHM_ED25519_MLDSA65);
    out.extend_from_slice(&key.ed25519_public_key);
    put_bytes(&mut out, &key.ml_dsa65_public_key);
    out
}

fn decode_public_key(bytes: &[u8]) -> Result<OwnerSigningPublicKey> {
    let mut reader = Reader::new(bytes);
    reader.magic(SIGNING_PUBLIC_MAGIC)?;
    reader.version()?;
    reader.algorithm()?;
    let ed25519_public_key = reader.array32()?;
    let ml_dsa65_public_key = reader.bytes()?;
    reader.done()?;
    Ok(OwnerSigningPublicKey {
        ed25519_public_key,
        ml_dsa65_public_key,
    })
}

fn encode_private_key_record(
    ed25519_seed: &[u8; ED25519_SEED_LEN],
    ml_dsa65_seed: &[u8],
) -> Result<SecretVec> {
    let mut out = SecretVec::new();
    out.try_extend_from_slice(SIGNING_PRIVATE_MAGIC)?;
    out.try_extend_from_slice(&SIGNING_KEY_VERSION.to_le_bytes())?;
    out.try_extend_from_slice(&SIGNING_ALGORITHM_ED25519_MLDSA65.to_le_bytes())?;
    out.try_extend_from_slice(ed25519_seed)?;
    out.try_extend_from_slice(&(ml_dsa65_seed.len() as u32).to_le_bytes())?;
    out.try_extend_from_slice(ml_dsa65_seed)?;
    Ok(out)
}

fn decode_private_key_record(
    bytes: &[u8],
) -> Result<([u8; ED25519_SEED_LEN], [u8; ML_DSA_SEED_LEN])> {
    let mut reader = Reader::new(bytes);
    reader.magic(SIGNING_PRIVATE_MAGIC)?;
    reader.version()?;
    reader.algorithm()?;
    let ed25519_seed = reader.array32()?;
    let ml_dsa65_seed = reader.array32_bytes()?;
    reader.done()?;
    Ok((ed25519_seed, ml_dsa65_seed))
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
                "owner signing key has invalid magic".to_string(),
            ));
        }
        self.offset += expected.len();
        Ok(())
    }

    fn version(&mut self) -> Result<()> {
        let version = self.u16()?;
        if version != SIGNING_KEY_VERSION {
            return Err(Error::InvalidKeyMaterial(format!(
                "owner signing key version {version} is not supported"
            )));
        }
        Ok(())
    }

    fn algorithm(&mut self) -> Result<()> {
        let algorithm = self.u16()?;
        if algorithm != SIGNING_ALGORITHM_ED25519_MLDSA65 {
            return Err(Error::InvalidKeyMaterial(format!(
                "owner signing key algorithm {algorithm} is not supported"
            )));
        }
        Ok(())
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        let bytes = self.take(4)?;
        let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn array32(&mut self) -> Result<[u8; 32]> {
        let bytes = self.take(32)?;
        let mut out = [0_u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn array32_bytes(&mut self) -> Result<[u8; 32]> {
        let bytes = self.bytes()?;
        bytes.try_into().map_err(|_| {
            Error::InvalidKeyMaterial("owner signing key seed has the wrong length".to_string())
        })
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(len).ok_or_else(|| {
            Error::InvalidKeyMaterial("owner signing key length overflow".to_string())
        })?;
        let slice = self.bytes.get(self.offset..end).ok_or_else(|| {
            Error::InvalidKeyMaterial("owner signing key is truncated".to_string())
        })?;
        self.offset = end;
        Ok(slice)
    }

    fn done(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::InvalidKeyMaterial(
                "owner signing key has trailing bytes".to_string(),
            ))
        }
    }
}
