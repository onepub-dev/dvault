use crate::compression::{
    decode_compression_frame, encode_compression_frame, MAX_DECOMPRESSED_COMPRESSION_FRAME_BYTES,
};
use crate::compression_frame_manifest::{
    decode_compression_frame_manifest, encode_compression_frame_manifest, CompressionFrameManifest,
};
#[cfg(test)]
use crate::lockbox_path::validate_stored_path as validate_path;
use crate::lockbox_path::validate_symlink_paths as validate_symlink;
#[cfg(test)]
use crate::security::validate_permissions;
use crate::{Error, LockboxPath, Result};

const COMPRESSION_FRAME_SEGMENT_MAGIC: &[u8; 4] = b"LBCS";
const COMPRESSION_FRAME_SEGMENT_VERSION: u8 = 3;

#[cfg(test)]
fn encode_file_payload(path: &str, permissions: u32, data: &[u8]) -> Vec<u8> {
    let path_bytes = path.as_bytes();
    let mut out = Vec::with_capacity(2 + path_bytes.len() + 4 + 8 + data.len());
    out.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(path_bytes);
    out.extend_from_slice(&permissions.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
fn decode_file_payload(payload: &[u8]) -> Result<(String, u32, Vec<u8>)> {
    if payload.len() < 14 {
        return Err(Error::CorruptRecord);
    }
    let path_len = u16::from_le_bytes(payload[0..2].try_into().unwrap()) as usize;
    if payload.len() < 2 + path_len + 4 + 8 {
        return Err(Error::CorruptRecord);
    }
    let path =
        String::from_utf8(payload[2..2 + path_len].to_vec()).map_err(|_| Error::CorruptRecord)?;
    validate_path(&path)?;
    let permissions_start = 2 + path_len;
    let permissions = u32::from_le_bytes(
        payload[permissions_start..permissions_start + 4]
            .try_into()
            .unwrap(),
    );
    let permissions = validate_permissions(permissions)?;
    let data_len_start = permissions_start + 4;
    let data_len_u64 = u64::from_le_bytes(
        payload[data_len_start..data_len_start + 8]
            .try_into()
            .unwrap(),
    );
    let data_len = usize::try_from(data_len_u64).map_err(|_| Error::CorruptRecord)?;
    let data_start = data_len_start + 8;
    if payload.len() != data_start + data_len {
        return Err(Error::CorruptRecord);
    }
    Ok((
        path,
        permissions,
        payload[data_start..data_start + data_len].to_vec(),
    ))
}

pub(crate) fn encode_compression_frame_segment_payload(
    manifest: &CompressionFrameManifest,
    segment_offset: u64,
    segment: &[u8],
) -> Result<Vec<u8>> {
    let manifest_bytes = if segment_offset == 0 {
        encode_compression_frame_manifest(manifest)?
    } else {
        Vec::new()
    };
    let (manifest_compression, stored_manifest) = if manifest_bytes.is_empty() {
        (crate::compression::COMPRESSION_NONE, Vec::new())
    } else {
        encode_compression_frame(&manifest_bytes)
    };
    let mut out = Vec::with_capacity(72 + stored_manifest.len() + segment.len());
    out.extend_from_slice(COMPRESSION_FRAME_SEGMENT_MAGIC);
    out.push(COMPRESSION_FRAME_SEGMENT_VERSION);
    put_varint(manifest.compression_frame_id, &mut out);
    put_varint(manifest.compression as u64, &mut out);
    put_varint(manifest.compression_frame_len, &mut out);
    put_varint(manifest.compressed_len, &mut out);
    out.extend_from_slice(&manifest.compression_frame_digest);
    put_varint(manifest_bytes.len() as u64, &mut out);
    put_varint(manifest_compression as u64, &mut out);
    put_varint(stored_manifest.len() as u64, &mut out);
    out.extend_from_slice(&stored_manifest);
    put_varint(segment_offset, &mut out);
    put_varint(segment.len() as u64, &mut out);
    out.extend_from_slice(segment);
    Ok(out)
}

pub(crate) fn decode_compression_frame_segment_payload_view(
    payload: &[u8],
) -> Result<DecodedFileChunkView<'_>> {
    if payload.len() < COMPRESSION_FRAME_SEGMENT_MAGIC.len() + 1 {
        return Err(Error::CorruptRecord);
    }
    if &payload[..COMPRESSION_FRAME_SEGMENT_MAGIC.len()] != COMPRESSION_FRAME_SEGMENT_MAGIC {
        return Err(Error::CorruptRecord);
    }
    let mut offset = COMPRESSION_FRAME_SEGMENT_MAGIC.len();
    if payload[offset] != COMPRESSION_FRAME_SEGMENT_VERSION {
        return Err(Error::CorruptRecord);
    }
    offset += 1;
    let compression_frame_id = take_varint(payload, &mut offset)?;
    let compression =
        u8::try_from(take_varint(payload, &mut offset)?).map_err(|_| Error::CorruptRecord)?;
    let compression_frame_len = take_varint(payload, &mut offset)?;
    if compression_frame_len > MAX_DECOMPRESSED_COMPRESSION_FRAME_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "compression-frame segment declares oversized frame".to_string(),
        ));
    }
    let compressed_len = take_varint(payload, &mut offset)?;
    if offset + 32 > payload.len() {
        return Err(Error::CorruptRecord);
    }
    let mut compression_frame_digest = [0u8; 32];
    compression_frame_digest.copy_from_slice(&payload[offset..offset + 32]);
    offset += 32;
    let manifest_len =
        usize::try_from(take_varint(payload, &mut offset)?).map_err(|_| Error::CorruptRecord)?;
    let manifest_compression =
        u8::try_from(take_varint(payload, &mut offset)?).map_err(|_| Error::CorruptRecord)?;
    let stored_manifest_len =
        usize::try_from(take_varint(payload, &mut offset)?).map_err(|_| Error::CorruptRecord)?;
    if stored_manifest_len > payload.len().saturating_sub(offset) {
        return Err(Error::CorruptRecord);
    }
    let manifest = if manifest_len == 0 {
        if stored_manifest_len != 0 {
            return Err(Error::CorruptRecord);
        }
        None
    } else {
        let manifest_bytes = decode_compression_frame(
            manifest_compression,
            &payload[offset..offset + stored_manifest_len],
            manifest_len as u64,
        )?;
        let manifest = decode_compression_frame_manifest(&manifest_bytes)?;
        if manifest.compression_frame_id != compression_frame_id
            || manifest.compression != compression
            || manifest.compression_frame_len != compression_frame_len
            || manifest.compressed_len != compressed_len
            || manifest.compression_frame_digest != compression_frame_digest
        {
            return Err(Error::CorruptRecord);
        }
        Some(manifest)
    };
    offset += stored_manifest_len;
    let segment_offset = take_varint(payload, &mut offset)?;
    let data_len =
        usize::try_from(take_varint(payload, &mut offset)?).map_err(|_| Error::CorruptRecord)?;
    if data_len > payload.len().saturating_sub(offset) || offset + data_len != payload.len() {
        return Err(Error::CorruptRecord);
    }
    if segment_offset
        .checked_add(data_len as u64)
        .is_none_or(|end| end > compressed_len)
    {
        return Err(Error::CorruptRecord);
    }
    Ok(DecodedFileChunkView {
        compression_frame_id,
        compression,
        compression_frame_len,
        compressed_len,
        compression_frame_digest,
        manifest,
        segment_offset,
        data: &payload[offset..],
    })
}

pub(crate) struct DecodedFileChunkView<'a> {
    pub(crate) compression_frame_id: u64,
    pub(crate) compression: u8,
    pub(crate) compression_frame_len: u64,
    pub(crate) compressed_len: u64,
    pub(crate) compression_frame_digest: [u8; 32],
    pub(crate) manifest: Option<CompressionFrameManifest>,
    pub(crate) segment_offset: u64,
    pub(crate) data: &'a [u8],
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

pub(crate) fn encode_symlink_payload(path: &LockboxPath, target: &LockboxPath) -> Vec<u8> {
    let path_bytes = path.as_str().as_bytes();
    let target_bytes = target.as_str().as_bytes();
    let mut out = Vec::with_capacity(2 + path_bytes.len() + 2 + target_bytes.len());
    out.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(path_bytes);
    out.extend_from_slice(&(target_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(target_bytes);
    out
}

pub(crate) fn decode_symlink_payload(payload: &[u8]) -> Result<(LockboxPath, LockboxPath)> {
    if payload.len() < 4 {
        return Err(Error::CorruptRecord);
    }
    let path_len = u16::from_le_bytes(payload[0..2].try_into().unwrap()) as usize;
    if payload.len() < 2 + path_len + 2 {
        return Err(Error::CorruptRecord);
    }
    let path =
        String::from_utf8(payload[2..2 + path_len].to_vec()).map_err(|_| Error::CorruptRecord)?;
    let path = LockboxPath::from_stored(&path, false)?;
    let target_len_start = 2 + path_len;
    let target_len = u16::from_le_bytes(
        payload[target_len_start..target_len_start + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let target_start = target_len_start + 2;
    if payload.len() != target_start + target_len {
        return Err(Error::CorruptRecord);
    }
    let target = String::from_utf8(payload[target_start..target_start + target_len].to_vec())
        .map_err(|_| Error::CorruptRecord)?;
    let target = LockboxPath::from_stored(&target, false)?;
    validate_symlink(path.as_str(), target.as_str())?;
    Ok((path, target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression_frame_manifest::{CompressionFrameManifest, CompressionFrameSlice};
    use crate::constants::DEFAULT_FILE_PERMISSIONS;

    #[test]
    fn decoded_file_payload_rejects_tampered_traversal_path() {
        let payload = encode_file_payload("/safe/../evil.txt", DEFAULT_FILE_PERMISSIONS, b"evil");
        assert!(matches!(
            decode_file_payload(&payload),
            Err(Error::InvalidPath(_))
        ));
    }

    #[test]
    fn compression_frame_manifest_is_stored_only_on_first_segment() {
        let manifest = CompressionFrameManifest {
            compression_frame_id: 7,
            compression: 1,
            compression_frame_len: 128,
            compressed_len: 12,
            compression_frame_digest: [3; 32],
            slices: vec![CompressionFrameSlice {
                path: LockboxPath::from_api("/a.txt", false).unwrap(),
                permissions: DEFAULT_FILE_PERMISSIONS,
                total_len: 128,
                file_offset: 0,
                compression_frame_offset: 0,
                len: 128,
            }],
        };

        let first = encode_compression_frame_segment_payload(&manifest, 0, b"abcdef").unwrap();
        let second = encode_compression_frame_segment_payload(&manifest, 6, b"ghijkl").unwrap();

        let first = decode_compression_frame_segment_payload_view(&first).unwrap();
        let second = decode_compression_frame_segment_payload_view(&second).unwrap();

        assert!(first.manifest.is_some());
        assert!(second.manifest.is_none());
        assert_eq!(first.compression_frame_id, second.compression_frame_id);
        assert_eq!(
            first.compression_frame_digest,
            second.compression_frame_digest
        );
        assert_eq!(second.segment_offset, 6);
    }
}
