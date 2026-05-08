use std::collections::BTreeMap;

use crate::file_chunk::FileChunk;
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::security::{validate_path, validate_permissions, validate_symlink};
use crate::{Error, Result};

pub(crate) fn encode_manifest(manifest: &BTreeMap<String, ManifestEntry>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    for entry in manifest.values() {
        out.extend_from_slice(&(entry.path.len() as u16).to_le_bytes());
        out.extend_from_slice(entry.path.as_bytes());
        out.extend_from_slice(&entry.len.to_le_bytes());
        out.extend_from_slice(&entry.record_offset.to_le_bytes());
        out.extend_from_slice(&entry.record_len.to_le_bytes());
        out.push(entry.deleted as u8);
        out.push(entry.node_kind as u8);
        out.extend_from_slice(&entry.permissions.to_le_bytes());
        if let Some(target) = &entry.symlink_target {
            out.extend_from_slice(&(target.len() as u16).to_le_bytes());
            out.extend_from_slice(target.as_bytes());
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        out.extend_from_slice(&(entry.chunks.len() as u32).to_le_bytes());
        for chunk in &entry.chunks {
            out.extend_from_slice(&chunk.record_offset.to_le_bytes());
            out.extend_from_slice(&chunk.record_len.to_le_bytes());
            out.extend_from_slice(&chunk.file_offset.to_le_bytes());
            out.extend_from_slice(&chunk.len.to_le_bytes());
            out.extend_from_slice(&chunk.segment_inner_offset.to_le_bytes());
            out.extend_from_slice(&chunk.segment_inner_len.to_le_bytes());
        }
    }
    out
}

pub(crate) fn decode_manifest(payload: &[u8]) -> Result<BTreeMap<String, ManifestEntry>> {
    if payload.len() < 4 {
        return Err(Error::CorruptRecord);
    }
    let count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    let mut offset = 4;
    let mut manifest = BTreeMap::new();
    for _ in 0..count {
        if offset + 2 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let path_len = u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if offset + path_len + 32 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let path = String::from_utf8(payload[offset..offset + path_len].to_vec())
            .map_err(|_| Error::CorruptRecord)?;
        validate_path(&path)?;
        offset += path_len;
        let len = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let record_offset = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let record_len = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let deleted = payload[offset] != 0;
        offset += 1;
        let node_kind = NodeKind::from_u8(payload[offset])?;
        offset += 1;
        let permissions = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        let permissions = validate_permissions(permissions)?;
        offset += 4;
        let target_len =
            u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if offset + target_len > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let symlink_target = if target_len == 0 {
            None
        } else {
            let target = String::from_utf8(payload[offset..offset + target_len].to_vec())
                .map_err(|_| Error::CorruptRecord)?;
            validate_symlink(&path, &target)?;
            Some(target)
        };
        offset += target_len;
        if offset + 4 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let chunk_count =
            u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let mut chunks = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            if offset + 48 > payload.len() {
                return Err(Error::CorruptRecord);
            }
            let record_offset = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let record_len = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let file_offset = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let chunk_len = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let segment_inner_offset =
                u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let segment_inner_len =
                u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;
            chunks.push(FileChunk {
                record_offset,
                record_len,
                file_offset,
                len: chunk_len,
                segment_inner_offset,
                segment_inner_len,
            });
        }
        match node_kind {
            NodeKind::File if symlink_target.is_some() => return Err(Error::CorruptRecord),
            NodeKind::Symlink if symlink_target.is_none() => return Err(Error::CorruptRecord),
            _ => {}
        }
        manifest.insert(
            path.clone(),
            ManifestEntry {
                path,
                len,
                record_offset,
                record_len,
                deleted,
                node_kind,
                permissions,
                symlink_target,
                chunks,
            },
        );
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_FILE_PERMISSIONS;

    #[test]
    fn decoded_manifest_rejects_tampered_host_paths() {
        let mut manifest = BTreeMap::new();
        manifest.insert(
            "/C:/Users/target.txt".to_string(),
            ManifestEntry {
                path: "/C:/Users/target.txt".to_string(),
                len: 1,
                record_offset: 64,
                record_len: 64,
                deleted: false,
                node_kind: NodeKind::File,
                permissions: DEFAULT_FILE_PERMISSIONS,
                symlink_target: None,
                chunks: Vec::new(),
            },
        );
        let payload = encode_manifest(&manifest);
        assert!(matches!(
            decode_manifest(&payload),
            Err(Error::InvalidPath(_))
        ));
    }
}
