use crate::key_slot::{slot_fingerprint, KeySlot};
use crate::key_wrap::MlKemWrappedKey;
use crate::lockbox_id::LockboxId;
use crate::storage::Storage;
use crate::{Error, Result};

const KEY_DIR_MAGIC: &[u8; 8] = b"LBX2KEY\0";
const KEY_DIR_HEADER_LEN: usize = 128;
const KEY_DIR_VERSION: u16 = 3;
const MAX_KEY_DIRECTORY_BYTES: usize = 1024 * 1024;
const KEY_DIR_HEADER_CHECKSUM_START: usize = 96;

#[derive(Debug, Clone)]
pub(crate) struct DecodedKeyDirectory {
    pub(crate) offset: u64,
    pub(crate) lockbox_id: LockboxId,
    pub(crate) generation: u64,
    pub(crate) copy_index: u32,
    pub(crate) slots: Vec<KeySlot>,
}

pub(crate) fn encode_key_directory(
    slots: &[KeySlot],
    lockbox_id: LockboxId,
    generation: u64,
    copy_index: u32,
) -> Result<Vec<u8>> {
    let payload = encode_key_slots(slots);
    let total_len = KEY_DIR_HEADER_LEN + payload.len();
    if total_len > MAX_KEY_DIRECTORY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "key directory exceeds 1 MiB".to_string(),
        ));
    }
    let mut out = vec![0; KEY_DIR_HEADER_LEN];
    out[0..8].copy_from_slice(KEY_DIR_MAGIC);
    out[8..10].copy_from_slice(&KEY_DIR_VERSION.to_le_bytes());
    out[12..16].copy_from_slice(&(KEY_DIR_HEADER_LEN as u32).to_le_bytes());
    out[16..24].copy_from_slice(&(total_len as u64).to_le_bytes());
    out[24..32].copy_from_slice(&generation.to_le_bytes());
    out[32..48].copy_from_slice(lockbox_id.as_bytes());
    out[48..52].copy_from_slice(&copy_index.to_le_bytes());
    out[56..88].copy_from_slice(&crate::crypto::strong_checksum(&payload));
    let header_digest = crate::crypto::strong_checksum(&out[0..KEY_DIR_HEADER_CHECKSUM_START]);
    out[KEY_DIR_HEADER_CHECKSUM_START..KEY_DIR_HEADER_LEN].copy_from_slice(&header_digest);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub(crate) fn read_key_directory(
    bytes: &[u8],
    offset: u64,
    expected_lockbox_id: Option<LockboxId>,
) -> Result<DecodedKeyDirectory> {
    if offset == 0 {
        return Err(Error::CorruptHeader);
    }
    let start = offset as usize;
    if start + KEY_DIR_HEADER_LEN > bytes.len() {
        return Err(Error::Truncated);
    }
    let header = &bytes[start..start + KEY_DIR_HEADER_LEN];
    if &header[0..8] != KEY_DIR_MAGIC {
        return Err(Error::CorruptHeader);
    }
    let header = decode_key_directory_header(header, expected_lockbox_id)?;
    let total_len = header.total_len;
    if total_len > MAX_KEY_DIRECTORY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "key directory exceeds 1 MiB".to_string(),
        ));
    }
    if total_len < KEY_DIR_HEADER_LEN || start + total_len > bytes.len() {
        return Err(Error::Truncated);
    }
    let payload = &bytes[start + KEY_DIR_HEADER_LEN..start + total_len];
    if crate::crypto::strong_checksum(payload) != header.payload_digest {
        return Err(Error::CorruptHeader);
    }
    Ok(DecodedKeyDirectory {
        offset,
        lockbox_id: header.lockbox_id,
        generation: header.generation,
        copy_index: header.copy_index,
        slots: decode_key_slots(payload)?,
    })
}

pub(crate) fn read_key_directory_from_storage(
    storage: &impl Storage,
    offset: u64,
    expected_lockbox_id: Option<LockboxId>,
) -> Result<DecodedKeyDirectory> {
    let header = storage.read_at(offset, KEY_DIR_HEADER_LEN)?;
    if &header[0..8] != KEY_DIR_MAGIC {
        return Err(Error::CorruptHeader);
    }
    let header = decode_key_directory_header(&header, expected_lockbox_id)?;
    let total_len = header.total_len;
    if total_len < KEY_DIR_HEADER_LEN {
        return Err(Error::Truncated);
    }
    let payload_len = total_len - KEY_DIR_HEADER_LEN;
    let payload = storage.read_at(offset + KEY_DIR_HEADER_LEN as u64, payload_len)?;
    if crate::crypto::strong_checksum(&payload) != header.payload_digest {
        return Err(Error::CorruptHeader);
    }
    Ok(DecodedKeyDirectory {
        offset,
        lockbox_id: header.lockbox_id,
        generation: header.generation,
        copy_index: header.copy_index,
        slots: decode_key_slots(&payload)?,
    })
}

pub(crate) fn scan_key_directories(
    bytes: &[u8],
    expected_lockbox_id: Option<LockboxId>,
) -> Vec<DecodedKeyDirectory> {
    let mut found = Vec::new();
    let mut offset = crate::constants::HEADER_LEN;
    while offset + KEY_DIR_HEADER_LEN <= bytes.len() {
        if &bytes[offset..offset + 8] == KEY_DIR_MAGIC {
            if let Ok(decoded) = read_key_directory(bytes, offset as u64, expected_lockbox_id) {
                let total_len =
                    u64::from_le_bytes(bytes[offset + 16..offset + 24].try_into().unwrap())
                        as usize;
                found.push(decoded);
                offset = offset.saturating_add(total_len.max(KEY_DIR_HEADER_LEN));
                continue;
            }
        }
        offset += 1;
    }
    found
}

pub(crate) fn best_key_directory(
    mut directories: Vec<DecodedKeyDirectory>,
) -> Option<DecodedKeyDirectory> {
    directories.sort_by_key(|directory| {
        (
            directory.generation,
            std::cmp::Reverse(directory.copy_index),
            directory.offset,
        )
    });
    directories.pop()
}

struct KeyDirectoryHeader {
    total_len: usize,
    lockbox_id: LockboxId,
    generation: u64,
    copy_index: u32,
    payload_digest: [u8; 32],
}

fn decode_key_directory_header(
    header: &[u8],
    expected_lockbox_id: Option<LockboxId>,
) -> Result<KeyDirectoryHeader> {
    if header.len() != KEY_DIR_HEADER_LEN || &header[0..8] != KEY_DIR_MAGIC {
        return Err(Error::CorruptHeader);
    }
    if u16::from_le_bytes(header[8..10].try_into().unwrap()) != KEY_DIR_VERSION {
        return Err(Error::CorruptHeader);
    }
    if header[10..12].iter().any(|byte| *byte != 0) {
        return Err(Error::CorruptHeader);
    }
    let header_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
    if header_len != KEY_DIR_HEADER_LEN {
        return Err(Error::CorruptHeader);
    }
    let total_len = u64::from_le_bytes(header[16..24].try_into().unwrap()) as usize;
    if total_len > MAX_KEY_DIRECTORY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "key directory exceeds 1 MiB".to_string(),
        ));
    }
    let lockbox_id = LockboxId::from_bytes(header[32..48].try_into().unwrap());
    if expected_lockbox_id.is_some_and(|expected| lockbox_id != expected) {
        return Err(Error::CorruptHeader);
    }
    if header[52..56].iter().any(|byte| *byte != 0) {
        return Err(Error::CorruptHeader);
    }
    if header[88..KEY_DIR_HEADER_CHECKSUM_START]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::CorruptHeader);
    }
    let header_digest = crate::crypto::strong_checksum(&header[0..KEY_DIR_HEADER_CHECKSUM_START]);
    if header[KEY_DIR_HEADER_CHECKSUM_START..KEY_DIR_HEADER_LEN] != header_digest {
        return Err(Error::CorruptHeader);
    }
    Ok(KeyDirectoryHeader {
        total_len,
        lockbox_id,
        generation: u64::from_le_bytes(header[24..32].try_into().unwrap()),
        copy_index: u32::from_le_bytes(header[48..52].try_into().unwrap()),
        payload_digest: header[56..88].try_into().unwrap(),
    })
}

fn encode_key_slots(slots: &[KeySlot]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(slots.len() as u32).to_le_bytes());
    for slot in slots {
        match slot {
            KeySlot::Password {
                id,
                salt,
                encrypted_key,
            } => {
                out.push(1);
                out.extend_from_slice(&id.to_le_bytes());
                write_bytes(&mut out, salt);
                write_bytes(&mut out, encrypted_key);
            }
            KeySlot::MlKem1024 { id, wrapped } => {
                out.push(2);
                out.extend_from_slice(&id.to_le_bytes());
                write_bytes(&mut out, wrapped.ciphertext_bytes());
                write_bytes(&mut out, wrapped.encrypted_key());
            }
        }
    }
    out
}

fn decode_key_slots(payload: &[u8]) -> Result<Vec<KeySlot>> {
    if payload.len() < 4 {
        return Err(Error::CorruptHeader);
    }
    let count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    let mut offset = 4usize;
    let mut slots = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 9 > payload.len() {
            return Err(Error::CorruptHeader);
        }
        let kind = payload[offset];
        offset += 1;
        let id = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
        offset += 8;
        match kind {
            1 => {
                let salt = read_bytes(payload, &mut offset)?;
                let encrypted_key = read_bytes(payload, &mut offset)?;
                slots.push(KeySlot::Password {
                    id,
                    salt,
                    encrypted_key,
                });
            }
            2 => {
                let ciphertext = read_bytes(payload, &mut offset)?;
                let encrypted_key = read_bytes(payload, &mut offset)?;
                slots.push(KeySlot::MlKem1024 {
                    id,
                    wrapped: Box::new(MlKemWrappedKey::from_parts(ciphertext, encrypted_key)?),
                });
            }
            _ => return Err(Error::CorruptHeader),
        }
    }
    Ok(slots)
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn read_bytes(payload: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    if *offset + 4 > payload.len() {
        return Err(Error::CorruptHeader);
    }
    let len = u32::from_le_bytes(payload[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    if *offset + len > payload.len() {
        return Err(Error::CorruptHeader);
    }
    let bytes = payload[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(bytes)
}

#[allow(dead_code)]
pub(crate) fn key_slot_id_for_bytes(bytes: &[u8]) -> u64 {
    slot_fingerprint(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_directory_header_numeric_fields_are_little_endian() {
        let lockbox_id = LockboxId::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let encoded =
            encode_key_directory(&[], lockbox_id, 0x0102_0304_0506_0708, 0x1112_1314).unwrap();

        assert_eq!(&encoded[0..8], KEY_DIR_MAGIC);
        assert_eq!(&encoded[8..10], &[0x03, 0x00]);
        assert_eq!(&encoded[12..16], &[0x80, 0x00, 0x00, 0x00]);
        assert_eq!(
            &encoded[16..24],
            &[0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            &encoded[24..32],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(&encoded[32..48], lockbox_id.as_bytes());
        assert_eq!(&encoded[48..52], &[0x14, 0x13, 0x12, 0x11]);

        let mut bytes = vec![0; crate::constants::HEADER_LEN];
        bytes.extend_from_slice(&encoded);
        let decoded = read_key_directory(
            &bytes,
            crate::constants::HEADER_LEN as u64,
            Some(lockbox_id),
        )
        .unwrap();
        assert_eq!(decoded.lockbox_id, lockbox_id);
        assert_eq!(decoded.generation, 0x0102_0304_0506_0708);
        assert_eq!(decoded.copy_index, 0x1112_1314);
        assert!(decoded.slots.is_empty());
    }

    #[test]
    fn key_directory_rejects_public_checksum_tampering() {
        let lockbox_id = LockboxId::new_random().unwrap();
        let encoded = encode_key_directory(&[], lockbox_id, 7, 0).unwrap();
        let mut bytes = vec![0; crate::constants::HEADER_LEN];
        bytes.extend_from_slice(&encoded);

        let offset = crate::constants::HEADER_LEN;
        bytes[offset + 24] ^= 0x01;

        assert!(matches!(
            read_key_directory(&bytes, offset as u64, Some(lockbox_id)),
            Err(Error::CorruptHeader)
        ));
    }
}
