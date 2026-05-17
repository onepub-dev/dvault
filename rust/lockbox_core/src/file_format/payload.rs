use crate::file_chunk::{DecodedFileChunk, PendingFileChunk};
use crate::lockbox_path::{
    validate_stored_path as validate_path, validate_symlink_paths as validate_symlink,
};
use crate::security::validate_permissions;
use crate::{Error, LockboxPath, Result};

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

pub(crate) fn encode_file_fragment_payload(
    chunk: &PendingFileChunk,
    compression: u8,
    frame_id: u64,
    frame_len: u64,
    compressed_len: u64,
    fragment_offset: u64,
) -> Vec<u8> {
    let path_bytes = chunk.path.as_str().as_bytes();
    let mut out = Vec::with_capacity(2 + path_bytes.len() + 4 + 8 * 5 + 2 + chunk.data.len());
    out.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(path_bytes);
    out.extend_from_slice(&chunk.permissions.to_le_bytes());
    out.extend_from_slice(&chunk.total_len.to_le_bytes());
    out.extend_from_slice(&chunk.file_offset.to_le_bytes());
    out.extend_from_slice(&frame_len.to_le_bytes());
    out.push(compression);
    out.push(0);
    out.extend_from_slice(&frame_id.to_le_bytes());
    out.extend_from_slice(&compressed_len.to_le_bytes());
    out.extend_from_slice(&fragment_offset.to_le_bytes());
    out.extend_from_slice(&(chunk.data.len() as u64).to_le_bytes());
    out.extend_from_slice(&chunk.data);
    out
}

pub(crate) fn decode_file_fragment_payload(payload: &[u8]) -> Result<DecodedFileChunk> {
    let view = decode_file_fragment_payload_view(payload)?;
    Ok(DecodedFileChunk {
        path: LockboxPath::from_stored(view.path, false)?,
        permissions: view.permissions,
        total_len: view.total_len,
        file_offset: view.file_offset,
        len: view.len,
        compressed_len: view.compressed_len,
        compression: view.compression,
        frame_id: view.frame_id,
        fragment_offset: view.fragment_offset,
        data: view.data.to_vec(),
    })
}

pub(crate) fn decode_file_fragment_payload_view(
    payload: &[u8],
) -> Result<DecodedFileChunkView<'_>> {
    if payload.len() < 2 {
        return Err(Error::CorruptRecord);
    }
    let path_len = u16::from_le_bytes(payload[0..2].try_into().unwrap()) as usize;
    if payload.len() < 2 + path_len + 4 + 8 * 6 + 2 {
        return Err(Error::CorruptRecord);
    }
    let mut offset = 2;
    let path = std::str::from_utf8(&payload[offset..offset + path_len])
        .map_err(|_| Error::CorruptRecord)?;
    validate_path(path)?;
    offset += path_len;
    let permissions = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
    let permissions = validate_permissions(permissions)?;
    offset += 4;
    let total_len = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let file_offset = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let len = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let compression = payload[offset];
    offset += 2;
    let frame_id = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let compressed_len = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let fragment_offset = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let data_len = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let data_len = usize::try_from(data_len).map_err(|_| Error::CorruptRecord)?;
    if offset + data_len != payload.len() {
        return Err(Error::CorruptRecord);
    }
    Ok(DecodedFileChunkView {
        path,
        permissions,
        total_len,
        file_offset,
        len,
        compressed_len,
        compression,
        frame_id,
        fragment_offset,
        data: &payload[offset..],
    })
}

pub(crate) struct DecodedFileChunkView<'a> {
    pub(crate) path: &'a str,
    pub(crate) permissions: u32,
    pub(crate) total_len: u64,
    pub(crate) file_offset: u64,
    pub(crate) len: u64,
    pub(crate) compressed_len: u64,
    pub(crate) compression: u8,
    pub(crate) frame_id: u64,
    pub(crate) fragment_offset: u64,
    pub(crate) data: &'a [u8],
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
    use crate::constants::DEFAULT_FILE_PERMISSIONS;

    #[test]
    fn decoded_file_payload_rejects_tampered_traversal_path() {
        let payload = encode_file_payload("/safe/../evil.txt", DEFAULT_FILE_PERMISSIONS, b"evil");
        assert!(matches!(
            decode_file_payload(&payload),
            Err(Error::InvalidPath(_))
        ));
    }
}
