use crate::file_chunk::{DecodedFileChunk, PendingFileChunk};
use crate::security::{
    validate_env_name, validate_env_value, validate_path, validate_permissions, validate_symlink,
};
use crate::{Error, Result};

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

pub(crate) fn decode_file_payload(payload: &[u8]) -> Result<(String, u32, Vec<u8>)> {
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

pub(crate) fn encode_file_segment_payload(chunks: &[PendingFileChunk]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
    for chunk in chunks {
        let path_bytes = chunk.path.as_bytes();
        out.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(path_bytes);
        out.extend_from_slice(&chunk.permissions.to_le_bytes());
        out.extend_from_slice(&chunk.total_len.to_le_bytes());
        out.extend_from_slice(&chunk.file_offset.to_le_bytes());
        out.extend_from_slice(&(chunk.data.len() as u64).to_le_bytes());
        out.extend_from_slice(&chunk.data);
    }
    out
}

pub(crate) fn decode_file_segment_payload(payload: &[u8]) -> Result<Vec<DecodedFileChunk>> {
    if payload.len() < 4 {
        return Err(Error::CorruptRecord);
    }
    let count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    let mut offset = 4usize;
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 2 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let path_len = u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if offset + path_len + 28 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let path = String::from_utf8(payload[offset..offset + path_len].to_vec())
            .map_err(|_| Error::CorruptRecord)?;
        validate_path(&path)?;
        offset += path_len;
        let permissions = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        let permissions = validate_permissions(permissions)?;
        offset += 4;
        let total_len = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let file_offset = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let data_len = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let data_len = usize::try_from(data_len).map_err(|_| Error::CorruptRecord)?;
        if offset + data_len > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let segment_inner_offset = offset as u64;
        let data = payload[offset..offset + data_len].to_vec();
        offset += data_len;
        chunks.push(DecodedFileChunk {
            path,
            permissions,
            total_len,
            file_offset,
            segment_inner_offset,
            data,
        });
    }
    if offset != payload.len() {
        return Err(Error::CorruptRecord);
    }
    Ok(chunks)
}

pub(crate) fn encode_symlink_payload(path: &str, target: &str) -> Vec<u8> {
    let path_bytes = path.as_bytes();
    let target_bytes = target.as_bytes();
    let mut out = Vec::with_capacity(2 + path_bytes.len() + 2 + target_bytes.len());
    out.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(path_bytes);
    out.extend_from_slice(&(target_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(target_bytes);
    out
}

pub(crate) fn decode_symlink_payload(payload: &[u8]) -> Result<(String, String)> {
    if payload.len() < 4 {
        return Err(Error::CorruptRecord);
    }
    let path_len = u16::from_le_bytes(payload[0..2].try_into().unwrap()) as usize;
    if payload.len() < 2 + path_len + 2 {
        return Err(Error::CorruptRecord);
    }
    let path =
        String::from_utf8(payload[2..2 + path_len].to_vec()).map_err(|_| Error::CorruptRecord)?;
    validate_path(&path)?;
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
    validate_symlink(&path, &target)?;
    Ok((path, target))
}

pub(crate) fn encode_delete_payload(path: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + path.len());
    out.extend_from_slice(&(path.len() as u16).to_le_bytes());
    out.extend_from_slice(path.as_bytes());
    out
}

pub(crate) fn decode_delete_payload(payload: &[u8]) -> Result<String> {
    if payload.len() < 2 {
        return Err(Error::CorruptRecord);
    }
    let path_len = u16::from_le_bytes(payload[0..2].try_into().unwrap()) as usize;
    if payload.len() < 2 + path_len {
        return Err(Error::CorruptRecord);
    }
    let path =
        String::from_utf8(payload[2..2 + path_len].to_vec()).map_err(|_| Error::CorruptRecord)?;
    validate_path(&path)?;
    Ok(path)
}

pub(crate) fn encode_env_payload(name: &str, value: &str) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let value_bytes = value.as_bytes();
    let mut out = Vec::with_capacity(2 + name_bytes.len() + 4 + value_bytes.len());
    out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(value_bytes);
    out
}

pub(crate) fn decode_env_payload(payload: &[u8]) -> Result<(String, String)> {
    if payload.len() < 6 {
        return Err(Error::CorruptRecord);
    }
    let name_len = u16::from_le_bytes(payload[0..2].try_into().unwrap()) as usize;
    if payload.len() < 2 + name_len + 4 {
        return Err(Error::CorruptRecord);
    }
    let name =
        String::from_utf8(payload[2..2 + name_len].to_vec()).map_err(|_| Error::CorruptRecord)?;
    let name = validate_env_name(&name)?;
    let value_len_start = 2 + name_len;
    let value_len = u32::from_le_bytes(
        payload[value_len_start..value_len_start + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let value_start = value_len_start + 4;
    if payload.len() != value_start + value_len {
        return Err(Error::CorruptRecord);
    }
    let value = String::from_utf8(payload[value_start..value_start + value_len].to_vec())
        .map_err(|_| Error::CorruptRecord)?;
    let value = validate_env_value(&value)?;
    Ok((name, value))
}

pub(crate) fn encode_env_delete_payload(name: &str) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut out = Vec::with_capacity(2 + name_bytes.len());
    out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(name_bytes);
    out
}

pub(crate) fn decode_env_delete_payload(payload: &[u8]) -> Result<String> {
    if payload.len() < 2 {
        return Err(Error::CorruptRecord);
    }
    let name_len = u16::from_le_bytes(payload[0..2].try_into().unwrap()) as usize;
    if payload.len() != 2 + name_len {
        return Err(Error::CorruptRecord);
    }
    let name =
        String::from_utf8(payload[2..2 + name_len].to_vec()).map_err(|_| Error::CorruptRecord)?;
    validate_env_name(&name)
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

    #[test]
    fn decoded_delete_payload_rejects_tampered_traversal_path() {
        let payload = encode_delete_payload("/safe/../evil.txt");
        assert!(matches!(
            decode_delete_payload(&payload),
            Err(Error::InvalidPath(_))
        ));
    }
}
