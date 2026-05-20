use crate::compression::MAX_DECOMPRESSED_COMPRESSION_FRAME_BYTES;
use crate::lockbox_path::{validate_stored_path, LockboxPath};
use crate::security::validate_permissions;
use crate::{Error, Result};

const MANIFEST_MAGIC: &[u8; 4] = b"LBFM";
const MANIFEST_VERSION: u8 = 1;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_SLICES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompressionFrameSlice {
    pub(crate) path: LockboxPath,
    pub(crate) permissions: u32,
    pub(crate) total_len: u64,
    pub(crate) file_offset: u64,
    pub(crate) compression_frame_offset: u64,
    pub(crate) len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompressionFrameManifest {
    pub(crate) compression_frame_id: u64,
    pub(crate) compression: u8,
    pub(crate) compression_frame_len: u64,
    pub(crate) compressed_len: u64,
    pub(crate) compression_frame_digest: [u8; 32],
    pub(crate) slices: Vec<CompressionFrameSlice>,
}

impl CompressionFrameManifest {
    pub(crate) fn slice_for(
        &self,
        path: &LockboxPath,
        file_offset: u64,
        compression_frame_offset: u64,
        len: u64,
    ) -> Option<&CompressionFrameSlice> {
        self.slices.iter().find(|slice| {
            slice.path == *path
                && slice.file_offset == file_offset
                && slice.compression_frame_offset == compression_frame_offset
                && slice.len == len
        })
    }
}

pub(crate) fn encode_compression_frame_manifest(
    manifest: &CompressionFrameManifest,
) -> Result<Vec<u8>> {
    if manifest.slices.len() > MAX_SLICES {
        return Err(Error::SecurityLimitExceeded(
            "compression-frame manifest contains too many slices".to_string(),
        ));
    }
    let mut out = Vec::new();
    out.extend_from_slice(MANIFEST_MAGIC);
    out.push(MANIFEST_VERSION);
    put_varint(manifest.compression_frame_id, &mut out);
    put_varint(manifest.compression as u64, &mut out);
    put_varint(manifest.compression_frame_len, &mut out);
    put_varint(manifest.compressed_len, &mut out);
    out.extend_from_slice(&manifest.compression_frame_digest);
    put_varint(manifest.slices.len() as u64, &mut out);
    for slice in &manifest.slices {
        let path = slice.path.as_str().as_bytes();
        put_varint(path.len() as u64, &mut out);
        out.extend_from_slice(path);
        put_varint(slice.permissions as u64, &mut out);
        put_varint(slice.total_len, &mut out);
        put_varint(slice.file_offset, &mut out);
        put_varint(slice.compression_frame_offset, &mut out);
        put_varint(slice.len, &mut out);
    }
    if out.len() > MAX_MANIFEST_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "compression-frame manifest exceeds safety limit".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn decode_compression_frame_manifest(
    payload: &[u8],
) -> Result<CompressionFrameManifest> {
    if payload.len() > MAX_MANIFEST_BYTES || payload.len() < MANIFEST_MAGIC.len() + 1 {
        return Err(Error::CorruptRecord);
    }
    if &payload[..MANIFEST_MAGIC.len()] != MANIFEST_MAGIC {
        return Err(Error::CorruptRecord);
    }
    let mut cursor = MANIFEST_MAGIC.len();
    if payload[cursor] != MANIFEST_VERSION {
        return Err(Error::CorruptRecord);
    }
    cursor += 1;
    let compression_frame_id = take_varint(payload, &mut cursor)?;
    let compression =
        u8::try_from(take_varint(payload, &mut cursor)?).map_err(|_| Error::CorruptRecord)?;
    let compression_frame_len = take_varint(payload, &mut cursor)?;
    if compression_frame_len > MAX_DECOMPRESSED_COMPRESSION_FRAME_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "compression-frame manifest declares oversized frame".to_string(),
        ));
    }
    let compressed_len = take_varint(payload, &mut cursor)?;
    if cursor + 32 > payload.len() {
        return Err(Error::CorruptRecord);
    }
    let mut compression_frame_digest = [0u8; 32];
    compression_frame_digest.copy_from_slice(&payload[cursor..cursor + 32]);
    cursor += 32;
    let slice_count =
        usize::try_from(take_varint(payload, &mut cursor)?).map_err(|_| Error::CorruptRecord)?;
    if slice_count > MAX_SLICES {
        return Err(Error::SecurityLimitExceeded(
            "compression-frame manifest contains too many slices".to_string(),
        ));
    }
    let mut slices = Vec::with_capacity(slice_count);
    for _ in 0..slice_count {
        let path_len = usize::try_from(take_varint(payload, &mut cursor)?)
            .map_err(|_| Error::CorruptRecord)?;
        if path_len > payload.len().saturating_sub(cursor) {
            return Err(Error::CorruptRecord);
        }
        let path = std::str::from_utf8(&payload[cursor..cursor + path_len])
            .map_err(|_| Error::CorruptRecord)?;
        validate_stored_path(path)?;
        let path = LockboxPath::from_stored(path, false)?;
        cursor += path_len;
        let permissions =
            u32::try_from(take_varint(payload, &mut cursor)?).map_err(|_| Error::CorruptRecord)?;
        let permissions = validate_permissions(permissions)?;
        let total_len = take_varint(payload, &mut cursor)?;
        let file_offset = take_varint(payload, &mut cursor)?;
        let compression_frame_offset = take_varint(payload, &mut cursor)?;
        let len = take_varint(payload, &mut cursor)?;
        let slice_end = compression_frame_offset
            .checked_add(len)
            .ok_or(Error::CorruptRecord)?;
        if slice_end > compression_frame_len {
            return Err(Error::CorruptRecord);
        }
        let file_end = file_offset.checked_add(len).ok_or(Error::CorruptRecord)?;
        if total_len != 0 && file_end > total_len {
            return Err(Error::CorruptRecord);
        }
        slices.push(CompressionFrameSlice {
            path,
            permissions,
            total_len,
            file_offset,
            compression_frame_offset,
            len,
        });
    }
    if cursor != payload.len() {
        return Err(Error::CorruptRecord);
    }
    Ok(CompressionFrameManifest {
        compression_frame_id,
        compression,
        compression_frame_len,
        compressed_len,
        compression_frame_digest,
        slices,
    })
}

fn put_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn take_varint(payload: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        if *cursor >= payload.len() {
            return Err(Error::CorruptRecord);
        }
        let byte = payload[*cursor];
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(Error::CorruptRecord)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trips_compact_binary_encoding() {
        let manifest = CompressionFrameManifest {
            compression_frame_id: 42,
            compression: 1,
            compression_frame_len: 11,
            compressed_len: 7,
            compression_frame_digest: [9; 32],
            slices: vec![
                CompressionFrameSlice {
                    path: LockboxPath::from_api("/a.txt", false).unwrap(),
                    permissions: 0o600,
                    total_len: 5,
                    file_offset: 0,
                    compression_frame_offset: 0,
                    len: 5,
                },
                CompressionFrameSlice {
                    path: LockboxPath::from_api("/b.txt", false).unwrap(),
                    permissions: 0o640,
                    total_len: 6,
                    file_offset: 0,
                    compression_frame_offset: 5,
                    len: 6,
                },
            ],
        };

        let encoded = encode_compression_frame_manifest(&manifest).unwrap();
        assert!(encoded.len() < 128);
        assert_eq!(
            decode_compression_frame_manifest(&encoded).unwrap(),
            manifest
        );
    }

    #[test]
    fn manifest_rejects_trailing_bytes() {
        let mut encoded = encode_compression_frame_manifest(&CompressionFrameManifest {
            compression_frame_id: 1,
            compression: 0,
            compression_frame_len: 0,
            compressed_len: 0,
            compression_frame_digest: [0; 32],
            slices: Vec::new(),
        })
        .unwrap();
        encoded.push(0);

        assert!(matches!(
            decode_compression_frame_manifest(&encoded),
            Err(Error::CorruptRecord)
        ));
    }
}
