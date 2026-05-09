use crate::key_slot::{slot_fingerprint, KeySlot};
use crate::key_wrap::MlKemWrappedKey;
use crate::storage::Storage;
use crate::{Error, Result};

const KEY_DIR_MAGIC: &[u8; 8] = b"LBX2KEY\0";
const KEY_DIR_HEADER_LEN: usize = 24;
const MAX_KEY_DIRECTORY_BYTES: usize = 1024 * 1024;

pub(crate) fn encode_key_directory(slots: &[KeySlot]) -> Result<Vec<u8>> {
    let payload = encode_key_slots(slots);
    let total_len = KEY_DIR_HEADER_LEN + payload.len();
    if total_len > MAX_KEY_DIRECTORY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "key directory exceeds 1 MiB".to_string(),
        ));
    }
    let mut out = vec![0; KEY_DIR_HEADER_LEN];
    out[0..8].copy_from_slice(KEY_DIR_MAGIC);
    out[8..16].copy_from_slice(&(total_len as u64).to_le_bytes());
    out[16..20].copy_from_slice(&crate::crypto::checksum(&payload).to_le_bytes());
    let header_crc = crate::crypto::checksum(&out[0..20]);
    out[20..24].copy_from_slice(&header_crc.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub(crate) fn read_key_directory(bytes: &[u8], offset: u64) -> Result<Vec<KeySlot>> {
    if offset == 0 {
        return Ok(Vec::new());
    }
    let start = offset as usize;
    if start + KEY_DIR_HEADER_LEN > bytes.len() {
        return Err(Error::Truncated);
    }
    if &bytes[start..start + 8] != KEY_DIR_MAGIC {
        return Err(Error::CorruptHeader);
    }
    let total_len = u64::from_le_bytes(bytes[start + 8..start + 16].try_into().unwrap()) as usize;
    if total_len > MAX_KEY_DIRECTORY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "key directory exceeds 1 MiB".to_string(),
        ));
    }
    let payload_crc = u32::from_le_bytes(bytes[start + 16..start + 20].try_into().unwrap());
    let header_crc = u32::from_le_bytes(bytes[start + 20..start + 24].try_into().unwrap());
    if crate::crypto::checksum(&bytes[start..start + 20]) != header_crc {
        return Err(Error::CorruptHeader);
    }
    if total_len < KEY_DIR_HEADER_LEN || start + total_len > bytes.len() {
        return Err(Error::Truncated);
    }
    let payload = &bytes[start + KEY_DIR_HEADER_LEN..start + total_len];
    if crate::crypto::checksum(payload) != payload_crc {
        return Err(Error::CorruptHeader);
    }
    decode_key_slots(payload)
}

pub(crate) fn read_key_directory_from_storage(
    storage: &impl Storage,
    offset: u64,
) -> Result<Vec<KeySlot>> {
    if offset == 0 {
        return Ok(Vec::new());
    }
    let header = storage.read_at(offset, KEY_DIR_HEADER_LEN)?;
    if &header[0..8] != KEY_DIR_MAGIC {
        return Err(Error::CorruptHeader);
    }
    let total_len = u64::from_le_bytes(header[8..16].try_into().unwrap()) as usize;
    if total_len > MAX_KEY_DIRECTORY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "key directory exceeds 1 MiB".to_string(),
        ));
    }
    let payload_crc = u32::from_le_bytes(header[16..20].try_into().unwrap());
    let header_crc = u32::from_le_bytes(header[20..24].try_into().unwrap());
    if crate::crypto::checksum(&header[0..20]) != header_crc {
        return Err(Error::CorruptHeader);
    }
    if total_len < KEY_DIR_HEADER_LEN {
        return Err(Error::Truncated);
    }
    let payload_len = total_len - KEY_DIR_HEADER_LEN;
    let payload = storage.read_at(offset + KEY_DIR_HEADER_LEN as u64, payload_len)?;
    if crate::crypto::checksum(&payload) != payload_crc {
        return Err(Error::CorruptHeader);
    }
    decode_key_slots(&payload)
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
