use crate::constants::{HEADER_LEN, HEADER_MAGIC};
use crate::crypto::checksum;
use crate::vault_id::VaultId;
use crate::{Error, Result};

pub(crate) fn write_header(
    bytes: &mut Vec<u8>,
    manifest_offset: u64,
    sequence: u64,
    key_directory_offset: u64,
    vault_id: VaultId,
) {
    if bytes.len() < HEADER_LEN {
        bytes.resize(HEADER_LEN, 0);
    }
    bytes[..HEADER_LEN].fill(0);
    bytes[0..8].copy_from_slice(HEADER_MAGIC);
    bytes[8..10].copy_from_slice(&2u16.to_le_bytes());
    bytes[16..24].copy_from_slice(&manifest_offset.to_le_bytes());
    bytes[24..32].copy_from_slice(&sequence.to_le_bytes());
    bytes[32..40].copy_from_slice(&key_directory_offset.to_le_bytes());
    bytes[40..56].copy_from_slice(vault_id.as_bytes());
    let crc = checksum(&bytes[0..60]);
    bytes[60..64].copy_from_slice(&crc.to_le_bytes());
}

pub(crate) fn read_header(bytes: &[u8]) -> Result<(u64, u64, u64, VaultId)> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::Truncated);
    }
    if &bytes[0..8] != HEADER_MAGIC {
        return Err(Error::CorruptHeader);
    }
    if u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != 2 {
        return Err(Error::CorruptHeader);
    }
    let expected = u32::from_le_bytes(bytes[60..64].try_into().unwrap());
    if checksum(&bytes[0..60]) != expected {
        return Err(Error::CorruptHeader);
    }
    let manifest_offset = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let sequence = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let key_directory_offset = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let vault_id = VaultId::from_bytes(bytes[40..56].try_into().unwrap());
    Ok((manifest_offset, sequence, key_directory_offset, vault_id))
}

pub fn read_vault_id(bytes: &[u8]) -> Result<VaultId> {
    let (_, _, _, vault_id) = read_header(bytes)?;
    Ok(vault_id)
}
