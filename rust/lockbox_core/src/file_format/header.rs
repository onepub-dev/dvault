use crate::constants::{HEADER_LEN, HEADER_MAGIC};
use crate::crypto::strong_checksum;
use crate::lockbox_id::LockboxId;
use crate::{Error, Result};

const HEADER_VERSION: u16 = 1;
const HEADER_CHECKSUM_START: usize = 64;

pub(crate) fn write_header(
    bytes: &mut Vec<u8>,
    toc_root_offset: u64,
    sequence: u64,
    key_directory_offset: u64,
    lockbox_id: LockboxId,
) {
    if bytes.len() < HEADER_LEN {
        bytes.resize(HEADER_LEN, 0);
    }
    bytes[..HEADER_LEN].fill(0);
    bytes[0..8].copy_from_slice(HEADER_MAGIC);
    bytes[8..10].copy_from_slice(&HEADER_VERSION.to_le_bytes());
    bytes[12..16].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&toc_root_offset.to_le_bytes());
    bytes[24..32].copy_from_slice(&sequence.to_le_bytes());
    bytes[32..40].copy_from_slice(&key_directory_offset.to_le_bytes());
    bytes[40..56].copy_from_slice(lockbox_id.as_bytes());
    let digest = strong_checksum(&bytes[0..HEADER_CHECKSUM_START]);
    bytes[HEADER_CHECKSUM_START..HEADER_LEN].copy_from_slice(&digest);
}

pub(crate) fn read_header(bytes: &[u8]) -> Result<(u64, u64, u64, LockboxId)> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::Truncated);
    }
    if &bytes[0..8] != HEADER_MAGIC {
        return Err(Error::CorruptHeader);
    }
    if u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != HEADER_VERSION {
        return Err(Error::CorruptHeader);
    }
    if u16::from_le_bytes(bytes[10..12].try_into().unwrap()) != 0 {
        return Err(Error::CorruptHeader);
    }
    if u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize != HEADER_LEN {
        return Err(Error::CorruptHeader);
    }
    if bytes[56..HEADER_CHECKSUM_START]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::CorruptHeader);
    }
    let expected = strong_checksum(&bytes[0..HEADER_CHECKSUM_START]);
    if bytes[HEADER_CHECKSUM_START..HEADER_LEN] != expected {
        return Err(Error::CorruptHeader);
    }
    let toc_root_offset = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let sequence = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let key_directory_offset = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let lockbox_id = LockboxId::from_bytes(bytes[40..56].try_into().unwrap());
    Ok((toc_root_offset, sequence, key_directory_offset, lockbox_id))
}

/// Read the lockbox id from encoded lockbox header bytes.
///
/// Returns `Error::CorruptHeader` if `bytes` do not contain a complete valid
/// lockbox header.
#[cfg(feature = "vault-bridge")]
pub fn read_lockbox_id(bytes: &[u8]) -> Result<LockboxId> {
    let (_, _, _, lockbox_id) = read_header(bytes)?;
    Ok(lockbox_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_numeric_fields_are_little_endian() {
        let lockbox_id = LockboxId::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let mut bytes = Vec::new();
        write_header(
            &mut bytes,
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            0x2122_2324_2526_2728,
            lockbox_id,
        );

        assert_eq!(&bytes[0..8], HEADER_MAGIC);
        assert_eq!(&bytes[8..10], &[0x01, 0x00]);
        assert_eq!(&bytes[12..16], &[0x60, 0x00, 0x00, 0x00]);
        assert_eq!(
            &bytes[16..24],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(
            &bytes[24..32],
            &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
        );
        assert_eq!(
            &bytes[32..40],
            &[0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21]
        );
        assert_eq!(&bytes[40..56], lockbox_id.as_bytes());
        assert_eq!(
            read_header(&bytes).unwrap(),
            (
                0x0102_0304_0506_0708,
                0x1112_1314_1516_1718,
                0x2122_2324_2526_2728,
                lockbox_id
            )
        );
    }

    #[test]
    fn header_rejects_public_checksum_tampering() {
        let lockbox_id = LockboxId::new_random().unwrap();
        let mut bytes = Vec::new();
        write_header(&mut bytes, 1, 2, 3, lockbox_id);

        bytes[16] ^= 0x01;

        assert!(matches!(read_header(&bytes), Err(Error::CorruptHeader)));
    }
}
