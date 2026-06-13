use crate::checked::{array_16, read_u16_le, read_u32_le, read_u64_le};
use crate::key_slot::{KeySlot, MAX_KEY_SLOT_NAME_BYTES};
use crate::key_wrap::RecipientWrappedKey;
use crate::lockbox_id::LockboxId;
use crate::page::{
    decode_page, page_decode_slice, physical_page_size_from_page_slice, DecodedPage,
    PageObjectKind, PAGE_HEADER_LEN,
};
use crate::page_cache::{PageCache, PageReadKey, PageSecurity};
use crate::storage::Storage;
use crate::{CacheLimit, Error, Result};

const KEY_DIR_MAGIC: &[u8; 8] = b"LBX2KEY\0";
const KEY_DIR_HEADER_LEN: usize = 64;
const KEY_DIR_VERSION: u16 = 5;
const MAX_KEY_DIRECTORY_BYTES: usize = 1024 * 1024;

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
    out.extend_from_slice(&payload);
    Ok(out)
}

pub(crate) fn read_key_directory(
    bytes: &[u8],
    offset: u64,
    expected_lockbox_id: Option<LockboxId>,
) -> Result<DecodedKeyDirectory> {
    let start = usize::try_from(offset).map_err(|_| Error::CorruptHeader)?;
    let page_bytes = page_decode_slice(bytes, start).ok_or(Error::CorruptHeader)?;
    decode_key_directory_page(page_bytes, offset, expected_lockbox_id)
}

#[cfg(any(test, feature = "vault-bridge"))]
pub(crate) fn read_key_directory_backup(bytes: &[u8]) -> Result<DecodedKeyDirectory> {
    if bytes.len() < KEY_DIR_HEADER_LEN || &bytes[0..8] != KEY_DIR_MAGIC {
        return Err(Error::CorruptHeader);
    }
    decode_key_directory_payload(bytes, 0, None)
}

pub(crate) fn read_key_directory_via_page_cache(
    storage: &impl Storage,
    offset: u64,
    expected_lockbox_id: Option<LockboxId>,
) -> Result<DecodedKeyDirectory> {
    let decode_lockbox_id = expected_lockbox_id.unwrap_or(LockboxId::from_bytes([0; 16]));
    let mut cache = PageCache::new(CacheLimit::Bytes(0));
    let page = cache.read_page(
        storage,
        offset,
        decode_lockbox_id,
        PageSecurity::Normal,
        PageReadKey::Normal(&[]),
    )?;
    decode_key_directory_decoded_page(&page, offset, expected_lockbox_id)
}

pub(crate) fn scan_key_directories(
    bytes: &[u8],
    expected_lockbox_id: Option<LockboxId>,
) -> Vec<DecodedKeyDirectory> {
    let mut found = Vec::new();
    let mut offset = crate::constants::HEADER_LEN;
    while offset + PAGE_HEADER_LEN <= bytes.len() {
        if bytes.get(offset..offset + 8) == Some(crate::page::PAGE_MAGIC.as_slice()) {
            if let Ok(decoded) = read_key_directory(bytes, offset as u64, expected_lockbox_id) {
                let page_size = page_decode_slice(bytes, offset)
                    .and_then(|page| physical_page_size_from_page_slice(page).ok())
                    .unwrap_or(crate::page::DEFAULT_METADATA_PAGE_BYTES);
                found.push(decoded);
                offset = offset.saturating_add(page_size);
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
}

fn decode_key_directory_header(
    header: &[u8],
    expected_lockbox_id: Option<LockboxId>,
) -> Result<KeyDirectoryHeader> {
    if header.len() != KEY_DIR_HEADER_LEN || &header[0..8] != KEY_DIR_MAGIC {
        return Err(Error::CorruptHeader);
    }
    if read_u16_le(&header[8..10]).map_err(|_| Error::CorruptHeader)? != KEY_DIR_VERSION {
        return Err(Error::CorruptHeader);
    }
    if header[10..12].iter().any(|byte| *byte != 0) {
        return Err(Error::CorruptHeader);
    }
    let header_len = read_u32_le(&header[12..16]).map_err(|_| Error::CorruptHeader)? as usize;
    if header_len != KEY_DIR_HEADER_LEN {
        return Err(Error::CorruptHeader);
    }
    let total_len = read_u64_le(&header[16..24]).map_err(|_| Error::CorruptHeader)? as usize;
    if total_len > MAX_KEY_DIRECTORY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "key directory exceeds 1 MiB".to_string(),
        ));
    }
    let lockbox_id =
        LockboxId::from_bytes(array_16(&header[32..48]).map_err(|_| Error::CorruptHeader)?);
    if expected_lockbox_id.is_some_and(|expected| lockbox_id != expected) {
        return Err(Error::CorruptHeader);
    }
    if header[52..KEY_DIR_HEADER_LEN].iter().any(|byte| *byte != 0) {
        return Err(Error::CorruptHeader);
    }
    Ok(KeyDirectoryHeader {
        total_len,
        lockbox_id,
        generation: read_u64_le(&header[24..32]).map_err(|_| Error::CorruptHeader)?,
        copy_index: read_u32_le(&header[48..52]).map_err(|_| Error::CorruptHeader)?,
    })
}

fn decode_key_directory_page(
    page_bytes: &[u8],
    offset: u64,
    expected_lockbox_id: Option<LockboxId>,
) -> Result<DecodedKeyDirectory> {
    let decode_lockbox_id = expected_lockbox_id.unwrap_or(LockboxId::from_bytes([0; 16]));
    let page = decode_page(page_bytes, decode_lockbox_id, &[])?;
    decode_key_directory_decoded_page(&page, offset, expected_lockbox_id)
}

pub(crate) fn decode_key_directory_decoded_page(
    page: &DecodedPage,
    offset: u64,
    expected_lockbox_id: Option<LockboxId>,
) -> Result<DecodedKeyDirectory> {
    let object = page
        .objects
        .iter()
        .find(|object| object.kind == PageObjectKind::KeyDirectory)
        .ok_or(Error::CorruptHeader)?;
    object.with_payload(|payload| {
        decode_key_directory_payload(payload, offset, expected_lockbox_id)
    })?
}

fn decode_key_directory_payload(
    bytes: &[u8],
    offset: u64,
    expected_lockbox_id: Option<LockboxId>,
) -> Result<DecodedKeyDirectory> {
    if bytes.len() < KEY_DIR_HEADER_LEN || &bytes[0..8] != KEY_DIR_MAGIC {
        return Err(Error::CorruptHeader);
    }
    let header = decode_key_directory_header(&bytes[0..KEY_DIR_HEADER_LEN], expected_lockbox_id)?;
    let total_len = header.total_len;
    if total_len < KEY_DIR_HEADER_LEN || total_len > bytes.len() {
        return Err(Error::Truncated);
    }
    Ok(DecodedKeyDirectory {
        offset,
        lockbox_id: header.lockbox_id,
        generation: header.generation,
        copy_index: header.copy_index,
        slots: decode_key_slots(&bytes[KEY_DIR_HEADER_LEN..total_len])?,
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
            KeySlot::HybridRecipient { id, name, wrapped } => {
                out.push(2);
                out.extend_from_slice(&id.to_le_bytes());
                write_optional_name(&mut out, name.as_deref());
                write_bytes(&mut out, wrapped.x25519_ephemeral_public_key());
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
    let count = read_u32_le(&payload[0..4]).map_err(|_| Error::CorruptHeader)? as usize;
    if count > (payload.len() - 4) / 9 {
        return Err(Error::CorruptHeader);
    }
    let mut offset = 4usize;
    let mut slots = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 9 > payload.len() {
            return Err(Error::CorruptHeader);
        }
        let kind = payload[offset];
        offset += 1;
        let id = read_u64_le(&payload[offset..offset + 8]).map_err(|_| Error::CorruptHeader)?;
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
                let name = read_optional_name(payload, &mut offset)?;
                let x25519_ephemeral_public_key = read_bytes(payload, &mut offset)?;
                let mlkem_ciphertext = read_bytes(payload, &mut offset)?;
                let encrypted_key = read_bytes(payload, &mut offset)?;
                slots.push(KeySlot::HybridRecipient {
                    id,
                    name,
                    wrapped: Box::new(RecipientWrappedKey::from_parts(
                        x25519_ephemeral_public_key,
                        mlkem_ciphertext,
                        encrypted_key,
                    )?),
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

fn write_optional_name(out: &mut Vec<u8>, name: Option<&str>) {
    let bytes = name.unwrap_or("").as_bytes();
    write_bytes(out, bytes);
}

fn read_optional_name(payload: &[u8], offset: &mut usize) -> Result<Option<String>> {
    if *offset + 4 > payload.len() {
        return Err(Error::CorruptHeader);
    }
    let len =
        read_u32_le(&payload[*offset..*offset + 4]).map_err(|_| Error::CorruptHeader)? as usize;
    *offset += 4;
    if len > MAX_KEY_SLOT_NAME_BYTES {
        return Err(Error::SecurityLimitExceeded(format!(
            "key slot name exceeds {MAX_KEY_SLOT_NAME_BYTES} bytes"
        )));
    }
    if *offset + len > payload.len() {
        return Err(Error::CorruptHeader);
    }
    if len == 0 {
        return Ok(None);
    }
    let value =
        std::str::from_utf8(&payload[*offset..*offset + len]).map_err(|_| Error::CorruptHeader)?;
    let valid_chars = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid_chars {
        return Err(Error::CorruptHeader);
    }
    *offset += len;
    Ok(Some(value.to_string()))
}

fn read_bytes(payload: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    if *offset + 4 > payload.len() {
        return Err(Error::CorruptHeader);
    }
    let len =
        read_u32_le(&payload[*offset..*offset + 4]).map_err(|_| Error::CorruptHeader)? as usize;
    *offset += 4;
    if *offset + len > payload.len() {
        return Err(Error::CorruptHeader);
    }
    let bytes = payload[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(bytes)
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
        assert_eq!(&encoded[8..10], &[0x05, 0x00]);
        assert_eq!(&encoded[12..16], &[0x40, 0x00, 0x00, 0x00]);
        assert_eq!(
            &encoded[16..24],
            &[0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            &encoded[24..32],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(&encoded[32..48], lockbox_id.as_bytes());
        assert_eq!(&encoded[48..52], &[0x14, 0x13, 0x12, 0x11]);

        let decoded = read_key_directory_backup(&encoded).unwrap();
        assert_eq!(decoded.lockbox_id, lockbox_id);
        assert_eq!(decoded.generation, 0x0102_0304_0506_0708);
        assert_eq!(decoded.copy_index, 0x1112_1314);
        assert!(decoded.slots.is_empty());
    }

    #[test]
    fn key_directory_rejects_reserved_field_tampering() {
        let lockbox_id = LockboxId::new_random().unwrap();
        let encoded = encode_key_directory(&[], lockbox_id, 7, 0).unwrap();
        let mut bytes = encoded;
        bytes[52] ^= 0x01;

        assert!(matches!(
            read_key_directory_backup(&bytes),
            Err(Error::CorruptHeader)
        ));
    }

    #[test]
    fn key_directory_rejects_oversized_slot_name() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.push(2);
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(&((MAX_KEY_SLOT_NAME_BYTES + 1) as u32).to_le_bytes());

        assert!(matches!(
            decode_key_slots(&payload),
            Err(Error::SecurityLimitExceeded(message)) if message.contains("key slot name exceeds")
        ));
    }
}
