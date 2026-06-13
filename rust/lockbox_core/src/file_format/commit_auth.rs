use crate::checked::{array_16, array_32, read_u16_le, read_u32_le, read_u64_le};
use crate::crypto::strong_checksum;
use crate::lockbox_id::LockboxId;
use crate::{Error, Result};

const COMMIT_AUTH_VERSION: u8 = 1;
const COMMIT_AUTH_MAGIC: &[u8; 8] = b"LBX2AUTH";
const SIGNED_CONTEXT: &[u8] = b"lockbox-v1-commit-auth";

pub(crate) const SIGNATURE_ALGORITHM_ED25519: u16 = 1;
pub(crate) const SIGNATURE_ALGORITHM_ML_DSA_65: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitAuth {
    pub(crate) lockbox_id: LockboxId,
    pub(crate) sequence: u64,
    pub(crate) commit_root_offset: u64,
    pub(crate) commit_root_digest: [u8; 32],
    pub(crate) previous_auth_offset: u64,
    pub(crate) previous_auth_digest: [u8; 32],
    pub(crate) flags: u64,
    pub(crate) signatures: Vec<CommitSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitSignature {
    pub(crate) algorithm: u16,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

pub(crate) fn commit_auth_digest(payload: &[u8]) -> [u8; 32] {
    strong_checksum(payload)
}

pub(crate) fn commit_auth_message(auth: &CommitAuth) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(SIGNED_CONTEXT);
    encode_signed_fields(auth, &mut out)?;
    Ok(out)
}

pub(crate) fn encode_commit_auth(auth: &CommitAuth) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(COMMIT_AUTH_MAGIC);
    out.push(COMMIT_AUTH_VERSION);
    out.extend_from_slice(&[0; 7]);
    encode_signed_fields(auth, &mut out)?;
    put_u32(&mut out, auth.signatures.len())?;
    for signature in &auth.signatures {
        put_u16(&mut out, signature.algorithm);
        put_bytes(&mut out, &signature.public_key)?;
        put_bytes(&mut out, &signature.signature)?;
    }
    Ok(out)
}

pub(crate) fn decode_commit_auth(payload: &[u8]) -> Result<CommitAuth> {
    let mut reader = Reader::new(payload);
    reader.magic(COMMIT_AUTH_MAGIC)?;
    if reader.u8()? != COMMIT_AUTH_VERSION {
        return Err(Error::CorruptRecord);
    }
    reader.zeroes(7)?;
    let lockbox_id = LockboxId::from_bytes(reader.array16()?);
    let sequence = reader.u64()?;
    let commit_root_offset = reader.u64()?;
    let commit_root_digest = reader.array32()?;
    let previous_auth_offset = reader.u64()?;
    let previous_auth_digest = reader.array32()?;
    let flags = reader.u64()?;
    let key_count = reader.u32()? as usize;
    let mut key_headers = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let algorithm = reader.u16()?;
        let public_key = reader.bytes()?;
        key_headers.push((algorithm, public_key));
    }
    let signature_count = reader.u32()? as usize;
    if signature_count != key_headers.len() {
        return Err(Error::CorruptRecord);
    }
    let mut signatures = Vec::with_capacity(signature_count);
    for (algorithm, public_key) in key_headers {
        let signature_algorithm = reader.u16()?;
        if signature_algorithm != algorithm {
            return Err(Error::CorruptRecord);
        }
        let signature_public_key = reader.bytes()?;
        if signature_public_key != public_key {
            return Err(Error::CorruptRecord);
        }
        let signature = reader.bytes()?;
        signatures.push(CommitSignature {
            algorithm,
            public_key,
            signature,
        });
    }
    reader.done()?;
    Ok(CommitAuth {
        lockbox_id,
        sequence,
        commit_root_offset,
        commit_root_digest,
        previous_auth_offset,
        previous_auth_digest,
        flags,
        signatures,
    })
}

fn encode_signed_fields(auth: &CommitAuth, out: &mut Vec<u8>) -> Result<()> {
    out.extend_from_slice(auth.lockbox_id.as_bytes());
    out.extend_from_slice(&auth.sequence.to_le_bytes());
    out.extend_from_slice(&auth.commit_root_offset.to_le_bytes());
    out.extend_from_slice(&auth.commit_root_digest);
    out.extend_from_slice(&auth.previous_auth_offset.to_le_bytes());
    out.extend_from_slice(&auth.previous_auth_digest);
    out.extend_from_slice(&auth.flags.to_le_bytes());
    put_u32(out, auth.signatures.len())?;
    for signature in &auth.signatures {
        put_u16(out, signature.algorithm);
        put_bytes(out, &signature.public_key)?;
    }
    Ok(())
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u32::try_from(value)
        .map_err(|_| Error::SecurityLimitExceeded("commit auth field is too large".to_string()))?;
    out.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    put_u32(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
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
        if self.take(expected.len())? != expected {
            return Err(Error::CorruptRecord);
        }
        Ok(())
    }

    fn zeroes(&mut self, len: usize) -> Result<()> {
        if self.take(len)?.iter().any(|byte| *byte != 0) {
            return Err(Error::CorruptRecord);
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        read_u16_le(self.take(2)?)
    }

    fn u32(&mut self) -> Result<u32> {
        read_u32_le(self.take(4)?)
    }

    fn u64(&mut self) -> Result<u64> {
        read_u64_le(self.take(8)?)
    }

    fn array16(&mut self) -> Result<[u8; 16]> {
        array_16(self.take(16)?)
    }

    fn array32(&mut self) -> Result<[u8; 32]> {
        array_32(self.take(32)?)
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(len).ok_or(Error::CorruptRecord)?;
        let slice = self.bytes.get(self.offset..end).ok_or(Error::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn done(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::CorruptRecord)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_auth_round_trips() {
        let auth = CommitAuth {
            lockbox_id: LockboxId::from_bytes([1; 16]),
            sequence: 7,
            commit_root_offset: 1024,
            commit_root_digest: [2; 32],
            previous_auth_offset: 512,
            previous_auth_digest: [3; 32],
            flags: 9,
            signatures: vec![
                CommitSignature {
                    algorithm: SIGNATURE_ALGORITHM_ED25519,
                    public_key: vec![4; 32],
                    signature: vec![5; 64],
                },
                CommitSignature {
                    algorithm: SIGNATURE_ALGORITHM_ML_DSA_65,
                    public_key: vec![6; 1952],
                    signature: vec![7; 3309],
                },
            ],
        };

        let decoded = decode_commit_auth(&encode_commit_auth(&auth).unwrap()).unwrap();

        assert_eq!(decoded, auth);
    }
}
