#![allow(dead_code)]

use crate::compression::{decode_page_body, encode_page_body};
use crate::crypto::{open_with_nonce, seal_with_random_nonce, strong_checksum};
use crate::lockbox_id::LockboxId;
use crate::page_inspection::{PageInspection, PageObjectInspection};
use crate::record::{DecodedRecord, RecordHeader, RecordKind};
use crate::scan::Scan;
use crate::{Error, Result};

pub(crate) const PAGE_MAGIC: &[u8; 8] = b"LBX2PAG\0";
pub(crate) const PAGE_HEADER_LEN: usize = 96;
pub(crate) use crate::constants::DEFAULT_PAGE_BYTES;

const PAGE_VERSION: u16 = 2;
const PAGE_BODY_VERSION: u8 = 1;
const COMPRESSION_NORMAL: u8 = 1;
const PAGE_UNCOMPRESSED_BODY_OVERHEAD: usize = 16 + 17 + 16;
const PAGE_CHECKSUM_START: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageObjectKind {
    CommitRoot = 1,
    TocLeaf = 2,
    TocInternal = 3,
    FileData = 4,
    PackedFileData = 5,
    Symlink = 6,
    EnvSet = 7,
    EnvDelete = 8,
    KeyDirectory = 9,
    FreeIndexLeaf = 10,
    FreeIndexInternal = 11,
    Delete = 12,
}

impl PageObjectKind {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::CommitRoot),
            2 => Ok(Self::TocLeaf),
            3 => Ok(Self::TocInternal),
            4 => Ok(Self::FileData),
            5 => Ok(Self::PackedFileData),
            6 => Ok(Self::Symlink),
            7 => Ok(Self::EnvSet),
            8 => Ok(Self::EnvDelete),
            9 => Ok(Self::KeyDirectory),
            10 => Ok(Self::FreeIndexLeaf),
            11 => Ok(Self::FreeIndexInternal),
            12 => Ok(Self::Delete),
            _ => Err(Error::CorruptRecord),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PageObject {
    pub(crate) kind: PageObjectKind,
    pub(crate) id: u64,
    pub(crate) payload: Vec<u8>,
}

pub(crate) fn encoded_object_stream_len(objects: &[PageObject]) -> Result<usize> {
    let mut len = 4usize;
    for object in objects {
        len = len
            .checked_add(encoded_object_len(object)?)
            .ok_or_else(|| Error::SecurityLimitExceeded("page is too large".to_string()))?;
    }
    Ok(len)
}

pub(crate) fn encoded_object_len(object: &PageObject) -> Result<usize> {
    20usize
        .checked_add(object.payload.len())
        .ok_or_else(|| Error::SecurityLimitExceeded("page object is too large".to_string()))
}

pub(crate) fn uncompressed_objects_fit(page_size: usize, object_stream_len: usize) -> bool {
    PAGE_HEADER_LEN
        .checked_add(PAGE_UNCOMPRESSED_BODY_OVERHEAD)
        .and_then(|overhead| overhead.checked_add(object_stream_len))
        .is_some_and(|encoded_len| encoded_len <= page_size)
}

#[derive(Debug, Clone)]
pub(crate) struct DecodedPage {
    pub(crate) page_id: u64,
    pub(crate) sequence: u64,
    pub(crate) objects: Vec<PageObject>,
}

pub(crate) fn encode_page(
    page_size: usize,
    lockbox_id: LockboxId,
    page_id: u64,
    sequence: u64,
    key: &[u8],
    objects: &[PageObject],
) -> Result<Vec<u8>> {
    if page_size < PAGE_HEADER_LEN {
        return Err(Error::SecurityLimitExceeded(
            "page is smaller than the header".to_string(),
        ));
    }
    let object_stream = encode_object_stream(objects)?;
    let body = encode_page_body_plaintext(&object_stream);
    let encrypted_len = body
        .len()
        .checked_add(16)
        .ok_or_else(|| Error::SecurityLimitExceeded("page body is too large".to_string()))?;
    let encrypted_len = u32::try_from(encrypted_len)
        .map_err(|_| Error::SecurityLimitExceeded("page body is too large".to_string()))?;
    let aad = page_aad(lockbox_id, page_id, sequence, 0, encrypted_len);
    let (nonce, encrypted_body) = seal_with_random_nonce(&body, key, &aad);
    if PAGE_HEADER_LEN + encrypted_body.len() > page_size {
        return Err(Error::SecurityLimitExceeded(
            "page body exceeds fixed page size".to_string(),
        ));
    }

    let mut page = vec![0; page_size];
    page[0..8].copy_from_slice(PAGE_MAGIC);
    page[8..10].copy_from_slice(&PAGE_VERSION.to_le_bytes());
    page[12..16].copy_from_slice(&(PAGE_HEADER_LEN as u32).to_le_bytes());
    page[16..24].copy_from_slice(&page_id.to_le_bytes());
    page[24..32].copy_from_slice(&sequence.to_le_bytes());
    page[32..44].copy_from_slice(&nonce);
    page[44..48].copy_from_slice(&(encrypted_body.len() as u32).to_le_bytes());
    let header_digest = strong_checksum(&page[0..PAGE_CHECKSUM_START]);
    page[PAGE_CHECKSUM_START..PAGE_HEADER_LEN].copy_from_slice(&header_digest);
    page[PAGE_HEADER_LEN..PAGE_HEADER_LEN + encrypted_body.len()].copy_from_slice(&encrypted_body);
    Ok(page)
}

pub(crate) fn decode_page(page: &[u8], lockbox_id: LockboxId, key: &[u8]) -> Result<DecodedPage> {
    if page.len() < PAGE_HEADER_LEN {
        return Err(Error::Truncated);
    }
    if &page[0..8] != PAGE_MAGIC {
        return Err(Error::CorruptRecord);
    }
    if u16::from_le_bytes(page[8..10].try_into().unwrap()) != PAGE_VERSION {
        return Err(Error::CorruptRecord);
    }
    let flags = u16::from_le_bytes(page[10..12].try_into().unwrap());
    if flags != 0 {
        return Err(Error::CorruptRecord);
    }
    let header_len = u32::from_le_bytes(page[12..16].try_into().unwrap()) as usize;
    if header_len != PAGE_HEADER_LEN || header_len > page.len() {
        return Err(Error::CorruptRecord);
    }
    if page[48..PAGE_CHECKSUM_START].iter().any(|byte| *byte != 0) {
        return Err(Error::CorruptRecord);
    }
    let expected_digest = strong_checksum(&page[0..PAGE_CHECKSUM_START]);
    if page[PAGE_CHECKSUM_START..PAGE_HEADER_LEN] != expected_digest {
        return Err(Error::CorruptRecord);
    }

    let page_id = u64::from_le_bytes(page[16..24].try_into().unwrap());
    let sequence = u64::from_le_bytes(page[24..32].try_into().unwrap());
    let nonce = &page[32..44];
    let encrypted_len = u32::from_le_bytes(page[44..48].try_into().unwrap()) as usize;
    if header_len + encrypted_len > page.len() {
        return Err(Error::Truncated);
    }
    let aad = page_aad(lockbox_id, page_id, sequence, flags, encrypted_len as u32);
    let body = open_with_nonce(
        &page[header_len..header_len + encrypted_len],
        key,
        nonce,
        &aad,
    )?;
    let object_stream = decode_page_body_plaintext(&body)?;
    let objects = decode_object_stream(&object_stream)?;
    Ok(DecodedPage {
        page_id,
        sequence,
        objects,
    })
}

pub(crate) fn scan_page_records(bytes: &[u8], lockbox_id: LockboxId, key: &[u8]) -> Scan {
    let mut records = Vec::new();
    let mut corrupt_records = 0usize;
    let mut i = crate::constants::HEADER_LEN;
    while i + PAGE_HEADER_LEN <= bytes.len() {
        if &bytes[i..i + 8] == PAGE_MAGIC {
            if i + DEFAULT_PAGE_BYTES > bytes.len() {
                corrupt_records += 1;
                break;
            }
            match decode_page(&bytes[i..i + DEFAULT_PAGE_BYTES], lockbox_id, key) {
                Ok(page) => {
                    for object in page.objects {
                        if let Some(kind) = record_kind_from_object_kind(object.kind) {
                            records.push(DecodedRecord {
                                header: RecordHeader {
                                    kind,
                                    sequence: page.sequence,
                                    total_len: DEFAULT_PAGE_BYTES as u64,
                                },
                                offset: i as u64,
                                object_id: object.id,
                                payload: object.payload,
                            });
                        }
                    }
                    i += DEFAULT_PAGE_BYTES;
                }
                Err(_) => {
                    corrupt_records += 1;
                    i += 1;
                }
            }
        } else {
            i += 1;
        }
    }
    records.sort_by_key(|record| record.header.sequence);
    Scan {
        records,
        corrupt_records,
    }
}

pub(crate) fn inspect_pages(
    bytes: &[u8],
    lockbox_id: LockboxId,
    key: &[u8],
) -> Vec<PageInspection> {
    let mut pages = Vec::new();
    let mut i = crate::constants::HEADER_LEN;
    while i + PAGE_HEADER_LEN <= bytes.len() {
        if &bytes[i..i + 8] == PAGE_MAGIC {
            if i + DEFAULT_PAGE_BYTES > bytes.len() {
                break;
            }
            let page_bytes = &bytes[i..i + DEFAULT_PAGE_BYTES];
            if let Ok(decoded) = decode_page(page_bytes, lockbox_id, key) {
                let encrypted_body_len = u32::from_le_bytes(page_bytes[44..48].try_into().unwrap());
                let objects = decoded
                    .objects
                    .iter()
                    .map(|object| PageObjectInspection {
                        id: object.id,
                        kind: page_object_kind_name(object.kind),
                        payload_len: object.payload.len(),
                    })
                    .collect::<Vec<_>>();
                pages.push(PageInspection {
                    offset: i as u64,
                    page_id: decoded.page_id,
                    sequence: decoded.sequence,
                    encrypted_body_len,
                    object_count: objects.len(),
                    objects,
                });
                i += DEFAULT_PAGE_BYTES;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    pages
}

fn record_kind_from_object_kind(kind: PageObjectKind) -> Option<RecordKind> {
    match kind {
        PageObjectKind::PackedFileData | PageObjectKind::FileData => Some(RecordKind::FilePage),
        PageObjectKind::Symlink => Some(RecordKind::Symlink),
        PageObjectKind::EnvSet => Some(RecordKind::Env),
        PageObjectKind::EnvDelete => Some(RecordKind::EnvDelete),
        PageObjectKind::Delete => Some(RecordKind::Delete),
        PageObjectKind::TocLeaf | PageObjectKind::TocInternal => Some(RecordKind::TocNode),
        PageObjectKind::CommitRoot => Some(RecordKind::CommitRoot),
        PageObjectKind::FreeIndexLeaf | PageObjectKind::FreeIndexInternal => {
            Some(RecordKind::FreeIndex)
        }
        PageObjectKind::KeyDirectory => None,
    }
}

fn page_object_kind_name(kind: PageObjectKind) -> &'static str {
    match kind {
        PageObjectKind::CommitRoot => "commit-root",
        PageObjectKind::TocLeaf => "toc-leaf",
        PageObjectKind::TocInternal => "toc-internal",
        PageObjectKind::FileData => "file-data",
        PageObjectKind::PackedFileData => "packed-file-data",
        PageObjectKind::Symlink => "symlink",
        PageObjectKind::EnvSet => "env-set",
        PageObjectKind::EnvDelete => "env-delete",
        PageObjectKind::KeyDirectory => "key-directory",
        PageObjectKind::FreeIndexLeaf => "free-index-leaf",
        PageObjectKind::FreeIndexInternal => "free-index-internal",
        PageObjectKind::Delete => "delete",
    }
}

fn encode_page_body_plaintext(object_stream: &[u8]) -> Vec<u8> {
    let stored = encode_page_body(object_stream);
    let mut body = Vec::with_capacity(16 + stored.len());
    body.push(PAGE_BODY_VERSION);
    body.push(COMPRESSION_NORMAL);
    body.push(0);
    body.push(0);
    body.extend_from_slice(&(object_stream.len() as u64).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&stored);
    body
}

fn decode_page_body_plaintext(body: &[u8]) -> Result<Vec<u8>> {
    if body.len() < 16 {
        return Err(Error::CorruptRecord);
    }
    if body[0] != PAGE_BODY_VERSION || body[1] != COMPRESSION_NORMAL {
        return Err(Error::CorruptRecord);
    }
    let expected_len = u64::from_le_bytes(body[4..12].try_into().unwrap());
    let decoded = decode_page_body(&body[16..])?;
    if decoded.len() as u64 != expected_len {
        return Err(Error::CorruptRecord);
    }
    Ok(decoded)
}

fn encode_object_stream(objects: &[PageObject]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&(objects.len() as u32).to_le_bytes());
    for object in objects {
        out.push(object.kind as u8);
        out.push(1);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&object.id.to_le_bytes());
        out.extend_from_slice(&(object.payload.len() as u64).to_le_bytes());
        out.extend_from_slice(&object.payload);
    }
    Ok(out)
}

fn decode_object_stream(bytes: &[u8]) -> Result<Vec<PageObject>> {
    if bytes.len() < 4 {
        return Err(Error::CorruptRecord);
    }
    let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let mut offset = 4usize;
    let mut objects = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 20 > bytes.len() {
            return Err(Error::CorruptRecord);
        }
        let kind = PageObjectKind::from_u8(bytes[offset])?;
        let version = bytes[offset + 1];
        let flags = u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap());
        if version != 1 || flags != 0 {
            return Err(Error::CorruptRecord);
        }
        let id = u64::from_le_bytes(bytes[offset + 4..offset + 12].try_into().unwrap());
        let payload_len =
            u64::from_le_bytes(bytes[offset + 12..offset + 20].try_into().unwrap()) as usize;
        offset += 20;
        if offset + payload_len > bytes.len() {
            return Err(Error::CorruptRecord);
        }
        objects.push(PageObject {
            kind,
            id,
            payload: bytes[offset..offset + payload_len].to_vec(),
        });
        offset += payload_len;
    }
    if offset != bytes.len() {
        return Err(Error::CorruptRecord);
    }
    Ok(objects)
}

fn page_aad(
    lockbox_id: LockboxId,
    page_id: u64,
    sequence: u64,
    flags: u16,
    encrypted_len: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 2 + 16 + 8 + 8 + 2 + 4);
    aad.extend_from_slice(b"LBX2PAGE");
    aad.extend_from_slice(&PAGE_VERSION.to_le_bytes());
    aad.extend_from_slice(lockbox_id.as_bytes());
    aad.extend_from_slice(&page_id.to_le_bytes());
    aad.extend_from_slice(&sequence.to_le_bytes());
    aad.extend_from_slice(&flags.to_le_bytes());
    aad.extend_from_slice(&encrypted_len.to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_round_trips_objects_and_has_fixed_size() {
        let lockbox_id = LockboxId::new_random().unwrap();
        let key = b"secret";
        let objects = vec![
            PageObject {
                kind: PageObjectKind::TocLeaf,
                id: 10,
                payload: b"toc".to_vec(),
            },
            PageObject {
                kind: PageObjectKind::PackedFileData,
                id: 11,
                payload: b"file".to_vec(),
            },
        ];

        let page = encode_page(128 * 1024, lockbox_id, 3, 7, key, &objects).unwrap();
        assert_eq!(page.len(), 128 * 1024);
        assert_eq!(&page[0..8], PAGE_MAGIC);

        let decoded = decode_page(&page, lockbox_id, key).unwrap();
        assert_eq!(decoded.page_id, 3);
        assert_eq!(decoded.sequence, 7);
        assert_eq!(decoded.objects, objects);
    }

    #[test]
    fn page_rejects_tampering() {
        let lockbox_id = LockboxId::new_random().unwrap();
        let key = b"secret";
        let objects = vec![PageObject {
            kind: PageObjectKind::TocLeaf,
            id: 10,
            payload: b"toc".to_vec(),
        }];

        let mut page = encode_page(128 * 1024, lockbox_id, 3, 7, key, &objects).unwrap();
        page[PAGE_HEADER_LEN + 8] ^= 0x01;

        assert!(decode_page(&page, lockbox_id, key).is_err());
    }

    #[test]
    fn page_rejects_public_header_checksum_tampering() {
        let lockbox_id = LockboxId::new_random().unwrap();
        let key = b"secret";
        let objects = vec![PageObject {
            kind: PageObjectKind::TocLeaf,
            id: 10,
            payload: b"toc".to_vec(),
        }];

        let mut page = encode_page(128 * 1024, lockbox_id, 3, 7, key, &objects).unwrap();
        page[16] ^= 0x01;

        assert!(decode_page(&page, lockbox_id, key).is_err());
    }
}
