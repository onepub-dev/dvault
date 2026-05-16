#![allow(dead_code)]

use crate::compression::{decode_page_body, encode_page_body, COMPRESSION_NONE};
use crate::crypto::{
    derive_page_content_key, open_with_content_key_secure, open_with_nonce,
    seal_with_content_key_secure, seal_with_random_nonce, strong_checksum,
};
use crate::lockbox_id::LockboxId;
use crate::page_buffer::PageBuffer;
use crate::page_inspection::{PageInspection, PageObjectInspection};
use crate::record::{DecodedRecord, RecordHeader, RecordKind};
use crate::scan::Scan;
use crate::secret_bytes::{secure_read_access, SecureVec};
use crate::{Error, Result};
use zeroize::Zeroize;

pub(crate) const PAGE_MAGIC: &[u8; 8] = b"LBX2PAG\0";
pub(crate) const PAGE_HEADER_LEN: usize = 96;
pub(crate) use crate::constants::{
    DEFAULT_DATA_PAGE_BYTES, DEFAULT_METADATA_PAGE_BYTES, DEFAULT_PAGE_BYTES,
};

const PAGE_VERSION: u16 = 2;
const PAGE_BODY_VERSION: u8 = 1;
const COMPRESSION_NORMAL: u8 = 1;
const PAGE_FLAG_CLEAR_TEXT: u16 = 0x0001;
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
    EnvLeaf = 13,
    EnvInternal = 14,
}

pub(crate) fn page_size_for_objects(objects: &[PageObject]) -> usize {
    if objects.iter().any(|object| {
        matches!(
            object.kind,
            PageObjectKind::FileData | PageObjectKind::PackedFileData
        )
    }) {
        DEFAULT_DATA_PAGE_BYTES
    } else {
        DEFAULT_METADATA_PAGE_BYTES
    }
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
            13 => Ok(Self::EnvLeaf),
            14 => Ok(Self::EnvInternal),
            _ => Err(Error::CorruptRecord),
        }
    }

    fn is_clear_text_page_object(self) -> bool {
        matches!(self, Self::KeyDirectory)
    }
}

#[derive(Debug)]
pub(crate) enum PagePayload {
    Normal(Vec<u8>),
    Secure(SecureVec),
}

impl PagePayload {
    pub(crate) fn normal(payload: Vec<u8>) -> Self {
        Self::Normal(payload)
    }

    pub(crate) fn secure(payload: SecureVec) -> Self {
        Self::Secure(payload)
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Normal(payload) => payload.len(),
            Self::Secure(payload) => payload.len(),
        }
    }

    pub(crate) fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        match self {
            Self::Normal(payload) => Ok(f(payload)),
            Self::Secure(payload) => {
                secure_read_access(|access| payload.with_bytes_in(access, f)).map_err(Into::into)
            }
        }
    }

    pub(crate) fn try_clone(&self) -> Result<Self> {
        match self {
            Self::Normal(payload) => Ok(Self::Normal(payload.clone())),
            Self::Secure(payload) => Ok(Self::Secure(payload.try_clone()?)),
        }
    }

    pub(crate) fn as_secure(&self) -> Option<&SecureVec> {
        match self {
            Self::Normal(_) => None,
            Self::Secure(payload) => Some(payload),
        }
    }
}

impl Drop for PagePayload {
    fn drop(&mut self) {
        if let Self::Normal(payload) = self {
            payload.zeroize();
        }
    }
}

impl Clone for PagePayload {
    fn clone(&self) -> Self {
        self.try_clone().expect("page payload clone failed")
    }
}

impl PartialEq for PagePayload {
    fn eq(&self, other: &Self) -> bool {
        self.with_bytes(|left| other.with_bytes(|right| left == right))
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false)
    }
}

impl Eq for PagePayload {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PageObject {
    pub(crate) kind: PageObjectKind,
    pub(crate) id: u64,
    pub(crate) payload: PagePayload,
}

impl PageObject {
    pub(crate) fn new(kind: PageObjectKind, id: u64, payload: Vec<u8>) -> Self {
        Self {
            kind,
            id,
            payload: PagePayload::normal(payload),
        }
    }

    pub(crate) fn new_secure(kind: PageObjectKind, id: u64, payload: SecureVec) -> Self {
        Self {
            kind,
            id,
            payload: PagePayload::secure(payload),
        }
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub(crate) fn with_payload<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        self.payload.with_bytes(f)
    }

    pub(crate) fn secure_payload(&self) -> Option<&SecureVec> {
        self.payload.as_secure()
    }
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
        .checked_add(object.payload_len())
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

pub(crate) struct SecureSingleObjectPage<'a> {
    pub(crate) page_size: usize,
    pub(crate) lockbox_id: LockboxId,
    pub(crate) page_id: u64,
    pub(crate) sequence: u64,
    pub(crate) content_key: &'a [u8; 32],
    pub(crate) kind: PageObjectKind,
    pub(crate) id: u64,
    pub(crate) payload: &'a SecureVec,
}

// Raw page codecs used by PageCache. Production lockbox read/write paths should
// not call these directly; recovery and low-level format tests are the
// exceptions for raw page codecs in this module.
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
    let clear_text = page_objects_are_clear_text(objects)?;
    let flags = if clear_text { PAGE_FLAG_CLEAR_TEXT } else { 0 };
    let (nonce, stored_body) = if clear_text {
        let mut stored = Vec::with_capacity(32 + body.len());
        stored.extend_from_slice(&strong_checksum(&body));
        stored.extend_from_slice(&body);
        ([0; 12], stored)
    } else {
        let encrypted_len = body
            .len()
            .checked_add(16)
            .ok_or_else(|| Error::SecurityLimitExceeded("page body is too large".to_string()))?;
        let encrypted_len = u32::try_from(encrypted_len)
            .map_err(|_| Error::SecurityLimitExceeded("page body is too large".to_string()))?;
        let aad = page_aad(lockbox_id, page_id, sequence, flags, encrypted_len);
        seal_with_random_nonce(&body, key, &aad)
    };
    let stored_body_len = u32::try_from(stored_body.len())
        .map_err(|_| Error::SecurityLimitExceeded("page body is too large".to_string()))?;
    if PAGE_HEADER_LEN + stored_body.len() > page_size {
        return Err(Error::SecurityLimitExceeded(
            "page body exceeds fixed page size".to_string(),
        ));
    }

    let mut page = vec![0; page_size];
    page[0..8].copy_from_slice(PAGE_MAGIC);
    page[8..10].copy_from_slice(&PAGE_VERSION.to_le_bytes());
    page[10..12].copy_from_slice(&flags.to_le_bytes());
    page[12..16].copy_from_slice(&(PAGE_HEADER_LEN as u32).to_le_bytes());
    page[16..24].copy_from_slice(&page_id.to_le_bytes());
    page[24..32].copy_from_slice(&sequence.to_le_bytes());
    page[32..44].copy_from_slice(&nonce);
    page[44..48].copy_from_slice(&stored_body_len.to_le_bytes());
    let header_digest = strong_checksum(&page[0..PAGE_CHECKSUM_START]);
    page[PAGE_CHECKSUM_START..PAGE_HEADER_LEN].copy_from_slice(&header_digest);
    page[PAGE_HEADER_LEN..PAGE_HEADER_LEN + stored_body.len()].copy_from_slice(&stored_body);
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
    if flags & !PAGE_FLAG_CLEAR_TEXT != 0 {
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
    let stored_body_len = u32::from_le_bytes(page[44..48].try_into().unwrap()) as usize;
    if header_len + stored_body_len > page.len() {
        return Err(Error::Truncated);
    }
    let stored_body = &page[header_len..header_len + stored_body_len];
    let body = if flags & PAGE_FLAG_CLEAR_TEXT != 0 {
        if nonce.iter().any(|byte| *byte != 0) || stored_body.len() < 32 {
            return Err(Error::CorruptRecord);
        }
        let (digest, body) = stored_body.split_at(32);
        if digest != strong_checksum(body) {
            return Err(Error::CorruptRecord);
        }
        body.to_vec()
    } else {
        let aad = page_aad(lockbox_id, page_id, sequence, flags, stored_body_len as u32);
        open_with_nonce(stored_body, key, nonce, &aad)?
    };
    let mut body = body;
    let mut object_stream = decode_page_body_plaintext(&body)?;
    body.zeroize();
    let objects = decode_object_stream(&object_stream)?;
    object_stream.zeroize();
    let clear_text = page_objects_are_clear_text(&objects)?;
    if clear_text != (flags & PAGE_FLAG_CLEAR_TEXT != 0) {
        return Err(Error::CorruptRecord);
    }
    Ok(DecodedPage {
        page_id,
        sequence,
        objects,
    })
}

pub(crate) fn decode_single_object_page_secure(
    page: &mut SecureVec,
    lockbox_id: LockboxId,
    content_key: &[u8; 32],
) -> Result<DecodedPage> {
    let (page_id, sequence) = decrypt_page_body_secure(page, lockbox_id, content_key)?;
    decode_page_body_plaintext_in_place(page)?;
    let (kind, id, payload) = decode_single_object_stream_in_place(page)?;
    let object = PageObject::new_secure(kind, id, payload);
    Ok(DecodedPage {
        page_id,
        sequence,
        objects: vec![object],
    })
}

pub(crate) fn encode_single_object_page_secure(
    request: SecureSingleObjectPage<'_>,
) -> Result<Vec<u8>> {
    if request.page_size < PAGE_HEADER_LEN {
        return Err(Error::SecurityLimitExceeded(
            "page is smaller than the header".to_string(),
        ));
    }
    if request.kind.is_clear_text_page_object() {
        return Err(Error::CorruptRecord);
    }

    let mut body = SecureVec::new();
    body.try_extend_from_slice(&1u32.to_le_bytes())?;
    body.try_extend_from_slice(&[request.kind as u8, 1])?;
    body.try_extend_from_slice(&0u16.to_le_bytes())?;
    body.try_extend_from_slice(&request.id.to_le_bytes())?;
    body.try_extend_from_slice(&(request.payload.len() as u64).to_le_bytes())?;
    body.try_extend_from_secure(request.payload)?;

    let object_stream_len = body.len();
    let mut page_body = SecureVec::new();
    page_body.try_extend_from_slice(&[PAGE_BODY_VERSION, COMPRESSION_NORMAL, 0, 0])?;
    page_body.try_extend_from_slice(&(object_stream_len as u64).to_le_bytes())?;
    page_body.try_extend_from_slice(&0u32.to_le_bytes())?;
    page_body.try_extend_from_slice(&(object_stream_len as u64).to_le_bytes())?;
    page_body.try_extend_from_slice(&[COMPRESSION_NONE])?;
    page_body.try_extend_from_slice(&(object_stream_len as u64).to_le_bytes())?;
    page_body.try_extend_from_secure(&body)?;
    body.zeroize()?;

    let encrypted_len = page_body
        .len()
        .checked_add(16)
        .ok_or_else(|| Error::SecurityLimitExceeded("page body is too large".to_string()))?;
    let encrypted_len = u32::try_from(encrypted_len)
        .map_err(|_| Error::SecurityLimitExceeded("page body is too large".to_string()))?;
    let aad = page_aad(
        request.lockbox_id,
        request.page_id,
        request.sequence,
        0,
        encrypted_len,
    );
    let nonce = seal_with_content_key_secure(&mut page_body, request.content_key, &aad)?;
    let stored_body_len = u32::try_from(page_body.len())
        .map_err(|_| Error::SecurityLimitExceeded("page body is too large".to_string()))?;
    if PAGE_HEADER_LEN + page_body.len() > request.page_size {
        return Err(Error::SecurityLimitExceeded(
            "page body exceeds fixed page size".to_string(),
        ));
    }

    let mut page = vec![0; request.page_size];
    page[0..8].copy_from_slice(PAGE_MAGIC);
    page[8..10].copy_from_slice(&PAGE_VERSION.to_le_bytes());
    page[10..12].copy_from_slice(&0u16.to_le_bytes());
    page[12..16].copy_from_slice(&(PAGE_HEADER_LEN as u32).to_le_bytes());
    page[16..24].copy_from_slice(&request.page_id.to_le_bytes());
    page[24..32].copy_from_slice(&request.sequence.to_le_bytes());
    page[32..44].copy_from_slice(&nonce);
    page[44..48].copy_from_slice(&stored_body_len.to_le_bytes());
    let header_digest = strong_checksum(&page[0..PAGE_CHECKSUM_START]);
    page[PAGE_CHECKSUM_START..PAGE_HEADER_LEN].copy_from_slice(&header_digest);
    secure_read_access(|access| {
        page_body.with_bytes_in(access, |encrypted| {
            page[PAGE_HEADER_LEN..PAGE_HEADER_LEN + encrypted.len()].copy_from_slice(encrypted);
        })
    })?;
    page_body.zeroize()?;
    Ok(page)
}

fn decrypt_page_body_secure(
    page: &mut SecureVec,
    lockbox_id: LockboxId,
    content_key: &[u8; 32],
) -> Result<(u64, u64)> {
    let header: (u64, u64, [u8; 12], u16, usize, usize) = secure_read_access(|access| {
        page.with_bytes_in(access, |page| {
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
            if flags & !PAGE_FLAG_CLEAR_TEXT != 0 {
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
            let stored_body_len = u32::from_le_bytes(page[44..48].try_into().unwrap()) as usize;
            if header_len + stored_body_len > page.len() {
                return Err(Error::Truncated);
            }
            Ok((
                u64::from_le_bytes(page[16..24].try_into().unwrap()),
                u64::from_le_bytes(page[24..32].try_into().unwrap()),
                page[32..44].try_into().unwrap(),
                flags,
                header_len,
                stored_body_len,
            ))
        })
    })??;
    let (page_id, sequence, nonce, flags, header_len, stored_body_len) = header;
    if flags & PAGE_FLAG_CLEAR_TEXT != 0 {
        return Err(Error::CorruptRecord);
    }
    page.with_mut_bytes(|bytes| {
        bytes.copy_within(header_len..header_len + stored_body_len, 0);
    })?;
    page.truncate(stored_body_len)?;
    let aad = page_aad(lockbox_id, page_id, sequence, flags, stored_body_len as u32);
    open_with_content_key_secure(page, content_key, &nonce, &aad)?;
    Ok((page_id, sequence))
}

fn decode_page_body_plaintext_in_place<B: PageBuffer>(body: &mut B) -> Result<()> {
    let (stored_offset, stored_len) = body.with_bytes(|body| {
        if body.len() < 33 {
            return Err(Error::CorruptRecord);
        }
        if body[0] != PAGE_BODY_VERSION || body[1] != COMPRESSION_NORMAL {
            return Err(Error::CorruptRecord);
        }
        let expected_len = u64::from_le_bytes(body[4..12].try_into().unwrap()) as usize;
        let compression = &body[16..];
        let real_len = u64::from_le_bytes(compression[0..8].try_into().unwrap()) as usize;
        let algorithm = compression[8];
        let stored_len = u64::from_le_bytes(compression[9..17].try_into().unwrap()) as usize;
        if algorithm != COMPRESSION_NONE {
            return Err(Error::CorruptRecord);
        }
        if expected_len != real_len || stored_len != real_len {
            return Err(Error::CorruptRecord);
        }
        let stored_offset = 16usize + 17;
        if stored_offset + stored_len > body.len() {
            return Err(Error::CorruptRecord);
        }
        Ok((stored_offset, stored_len))
    })??;
    body.with_mut_bytes(|bytes| {
        bytes.copy_within(stored_offset..stored_offset + stored_len, 0);
    })?;
    body.truncate(stored_len)?;
    Ok(())
}

fn decode_single_object_stream_in_place<B: PageBuffer>(
    stream: &mut B,
) -> Result<(PageObjectKind, u64, B)> {
    let (kind, id, payload_offset, payload_len) = stream.with_bytes(|bytes| {
        if bytes.len() < 24 {
            return Err(Error::CorruptRecord);
        }
        let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if count != 1 {
            return Err(Error::CorruptRecord);
        }
        let kind = PageObjectKind::from_u8(bytes[4])?;
        let version = bytes[5];
        let flags = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        if version != 1 || flags != 0 {
            return Err(Error::CorruptRecord);
        }
        let id = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let payload_len = u64::from_le_bytes(bytes[16..24].try_into().unwrap()) as usize;
        let payload_offset = 24usize;
        if payload_offset + payload_len != bytes.len() {
            return Err(Error::CorruptRecord);
        }
        Ok((kind, id, payload_offset, payload_len))
    })??;
    stream.with_mut_bytes(|bytes| {
        bytes.copy_within(payload_offset..payload_offset + payload_len, 0);
    })?;
    stream.truncate(payload_len)?;
    let payload = stream.try_clone_range(0, payload_len)?;
    Ok((kind, id, payload))
}

pub(crate) fn scan_page_records(bytes: &[u8], lockbox_id: LockboxId, key: &[u8]) -> Scan {
    let mut records = Vec::new();
    let mut corrupt_records = 0usize;
    let mut content_key = derive_page_content_key(key);
    let mut i = crate::constants::HEADER_LEN;
    while i + PAGE_HEADER_LEN <= bytes.len() {
        if &bytes[i..i + 8] == PAGE_MAGIC {
            let Some(page_bytes) = page_decode_slice(bytes, i) else {
                corrupt_records += 1;
                break;
            };
            if decode_secure_env_page_inspection(page_bytes, lockbox_id, &content_key).is_some() {
                i += DEFAULT_METADATA_PAGE_BYTES;
                continue;
            }
            match decode_page(page_bytes, lockbox_id, key) {
                Ok(page) => {
                    let page_size = page_size_for_objects(&page.objects);
                    for object in page.objects {
                        if let Some(kind) = record_kind_from_object_kind(object.kind) {
                            let Ok(payload) = object.with_payload(|payload| payload.to_vec())
                            else {
                                corrupt_records += 1;
                                continue;
                            };
                            records.push(DecodedRecord {
                                header: RecordHeader {
                                    kind,
                                    sequence: page.sequence,
                                    total_len: page_size as u64,
                                },
                                offset: i as u64,
                                object_id: object.id,
                                payload,
                            });
                        }
                    }
                    i += page_size;
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
    content_key.zeroize();
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
    let mut content_key = derive_page_content_key(key);
    let mut i = crate::constants::HEADER_LEN;
    while i + PAGE_HEADER_LEN <= bytes.len() {
        if &bytes[i..i + 8] == PAGE_MAGIC {
            let Some(page_bytes) = page_decode_slice(bytes, i) else {
                break;
            };
            if let Some(inspection) =
                inspect_secure_env_page(page_bytes, i as u64, lockbox_id, &content_key)
            {
                pages.push(inspection);
                i += DEFAULT_METADATA_PAGE_BYTES;
                continue;
            }
            if let Ok(decoded) = decode_page(page_bytes, lockbox_id, key) {
                let page_size = page_size_for_objects(&decoded.objects);
                let encrypted_body_len = u32::from_le_bytes(page_bytes[44..48].try_into().unwrap());
                let objects = decoded
                    .objects
                    .iter()
                    .map(|object| PageObjectInspection {
                        id: object.id,
                        kind: page_object_kind_name(object.kind),
                        payload_len: object.payload_len(),
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
                i += page_size;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    content_key.zeroize();
    pages
}

fn inspect_secure_env_page(
    page_bytes: &[u8],
    offset: u64,
    lockbox_id: LockboxId,
    content_key: &[u8; 32],
) -> Option<PageInspection> {
    let (page_id, sequence, stored_body_len) = public_page_header_metadata(page_bytes)?;
    let object = decode_secure_env_page_inspection(page_bytes, lockbox_id, content_key)?;
    Some(PageInspection {
        offset,
        page_id,
        sequence,
        encrypted_body_len: stored_body_len as u32,
        object_count: 1,
        objects: vec![object],
    })
}

fn decode_secure_env_page_inspection(
    page_bytes: &[u8],
    lockbox_id: LockboxId,
    content_key: &[u8; 32],
) -> Option<PageObjectInspection> {
    let mut page = SecureVec::try_from_slice(page_bytes).ok()?;
    let decoded = decode_single_object_page_secure(&mut page, lockbox_id, content_key).ok()?;
    let object = decoded.objects.first()?;
    if !matches!(
        object.kind,
        PageObjectKind::EnvLeaf | PageObjectKind::EnvInternal
    ) {
        return None;
    }
    Some(PageObjectInspection {
        id: object.id,
        kind: page_object_kind_name(object.kind),
        payload_len: object.payload_len(),
    })
}

fn public_page_header_metadata(page: &[u8]) -> Option<(u64, u64, usize)> {
    if page.len() < PAGE_HEADER_LEN || &page[0..8] != PAGE_MAGIC {
        return None;
    }
    Some((
        u64::from_le_bytes(page[16..24].try_into().ok()?),
        u64::from_le_bytes(page[24..32].try_into().ok()?),
        u32::from_le_bytes(page[44..48].try_into().ok()?) as usize,
    ))
}

pub(crate) fn page_decode_slice(bytes: &[u8], offset: usize) -> Option<&[u8]> {
    if offset + PAGE_HEADER_LEN > bytes.len() || bytes.get(offset..offset + 8)? != PAGE_MAGIC {
        return None;
    }
    let header_len =
        u32::from_le_bytes(bytes.get(offset + 12..offset + 16)?.try_into().ok()?) as usize;
    let encrypted_len =
        u32::from_le_bytes(bytes.get(offset + 44..offset + 48)?.try_into().ok()?) as usize;
    let len = header_len.checked_add(encrypted_len)?;
    bytes.get(offset..offset.checked_add(len)?)
}

fn page_objects_are_clear_text(objects: &[PageObject]) -> Result<bool> {
    let clear_text = objects
        .iter()
        .any(|object| object.kind.is_clear_text_page_object());
    if clear_text
        && objects
            .iter()
            .any(|object| !object.kind.is_clear_text_page_object())
    {
        return Err(Error::CorruptRecord);
    }
    Ok(clear_text)
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
        PageObjectKind::KeyDirectory | PageObjectKind::EnvLeaf | PageObjectKind::EnvInternal => {
            None
        }
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
        PageObjectKind::EnvLeaf => "env-leaf",
        PageObjectKind::EnvInternal => "env-internal",
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
        out.extend_from_slice(&(object.payload_len() as u64).to_le_bytes());
        object.with_payload(|payload| out.extend_from_slice(payload))?;
    }
    Ok(out)
}

fn decode_object_stream(bytes: &[u8]) -> Result<Vec<PageObject>> {
    if bytes.len() < 4 {
        return Err(Error::CorruptRecord);
    }
    let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if count > (bytes.len() - 4) / 20 {
        return Err(Error::CorruptRecord);
    }
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
        objects.push(PageObject::new(
            kind,
            id,
            bytes[offset..offset + payload_len].to_vec(),
        ));
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
            PageObject::new(PageObjectKind::TocLeaf, 10, b"toc".to_vec()),
            PageObject::new(PageObjectKind::PackedFileData, 11, b"file".to_vec()),
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
        let objects = vec![PageObject::new(
            PageObjectKind::TocLeaf,
            10,
            b"toc".to_vec(),
        )];

        let mut page = encode_page(128 * 1024, lockbox_id, 3, 7, key, &objects).unwrap();
        page[PAGE_HEADER_LEN + 8] ^= 0x01;

        assert!(decode_page(&page, lockbox_id, key).is_err());
    }

    #[test]
    fn page_rejects_public_header_checksum_tampering() {
        let lockbox_id = LockboxId::new_random().unwrap();
        let key = b"secret";
        let objects = vec![PageObject::new(
            PageObjectKind::TocLeaf,
            10,
            b"toc".to_vec(),
        )];

        let mut page = encode_page(128 * 1024, lockbox_id, 3, 7, key, &objects).unwrap();
        page[16] ^= 0x01;

        assert!(decode_page(&page, lockbox_id, key).is_err());
    }

    #[test]
    fn clear_text_page_uses_page_checksum_for_body_integrity() {
        let lockbox_id = LockboxId::new_random().unwrap();
        let objects = vec![PageObject::new(
            PageObjectKind::KeyDirectory,
            10,
            b"keys".to_vec(),
        )];

        let mut page = encode_page(128 * 1024, lockbox_id, 3, 7, b"", &objects).unwrap();
        assert_eq!(
            u16::from_le_bytes(page[10..12].try_into().unwrap()),
            PAGE_FLAG_CLEAR_TEXT
        );
        let decoded = decode_page(&page, LockboxId::from_bytes([0; 16]), b"").unwrap();
        assert_eq!(decoded.objects, objects);

        page[PAGE_HEADER_LEN + 40] ^= 0x01;
        assert!(decode_page(&page, LockboxId::from_bytes([0; 16]), b"").is_err());
    }

    #[test]
    fn secure_payload_can_be_read_only_through_scoped_access() {
        let payload = SecureVec::try_from_slice(b"secret").unwrap();
        let object = PageObject::new_secure(PageObjectKind::EnvLeaf, 10, payload);

        assert!(object.with_payload(|payload| payload == b"secret").unwrap());
    }
}
