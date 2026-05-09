use crate::file_chunk::{FileChunk, FileFragment};
use crate::logical_path::{
    validate_stored_path as validate_path, validate_symlink_paths as validate_symlink,
};
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::security::validate_permissions;
use crate::{Error, Result};

#[cfg(test)]
pub(crate) fn encode_manifest(
    manifest: &std::collections::BTreeMap<String, ManifestEntry>,
) -> Vec<u8> {
    encode_manifest_entries(manifest.values())
}

pub(crate) fn encode_manifest_entries<'a>(
    entries: impl IntoIterator<Item = &'a ManifestEntry>,
) -> Vec<u8> {
    let entries = entries.into_iter().collect::<Vec<_>>();
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
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
            out.extend_from_slice(&chunk.file_offset.to_le_bytes());
            out.extend_from_slice(&chunk.len.to_le_bytes());
            out.extend_from_slice(&chunk.compressed_len.to_le_bytes());
            out.push(chunk.compression);
            out.extend_from_slice(&0u16.to_le_bytes());
            out.push(0);
            out.extend_from_slice(&chunk.frame_id.to_le_bytes());
            out.extend_from_slice(&(chunk.fragments.len() as u32).to_le_bytes());
            for fragment in &chunk.fragments {
                out.extend_from_slice(&fragment.page_offset.to_le_bytes());
                out.extend_from_slice(&fragment.page_len.to_le_bytes());
                out.extend_from_slice(&fragment.object_id.to_le_bytes());
                out.extend_from_slice(&fragment.fragment_offset.to_le_bytes());
                out.extend_from_slice(&fragment.fragment_len.to_le_bytes());
            }
        }
    }
    out
}

#[cfg(test)]
pub(crate) fn decode_manifest(
    payload: &[u8],
) -> Result<std::collections::BTreeMap<String, ManifestEntry>> {
    Ok(decode_manifest_entries(payload)?
        .into_iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect())
}

pub(crate) fn decode_manifest_entries(payload: &[u8]) -> Result<Vec<ManifestEntry>> {
    if payload.len() < 4 {
        return Err(Error::CorruptRecord);
    }
    let count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    let mut offset = 4;
    let mut entries = Vec::with_capacity(count);
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
            if offset + 40 > payload.len() {
                return Err(Error::CorruptRecord);
            }
            let file_offset = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let chunk_len = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let compressed_len =
                u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let compression = payload[offset];
            offset += 4;
            let frame_id = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let fragment_count =
                u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            let mut fragments = Vec::with_capacity(fragment_count);
            for _ in 0..fragment_count {
                if offset + 40 > payload.len() {
                    return Err(Error::CorruptRecord);
                }
                let page_offset =
                    u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let page_len = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let object_id = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let fragment_offset =
                    u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let fragment_len =
                    u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
                offset += 8;
                fragments.push(FileFragment {
                    page_offset,
                    page_len,
                    object_id,
                    fragment_offset,
                    fragment_len,
                });
            }
            chunks.push(FileChunk {
                file_offset,
                len: chunk_len,
                compressed_len,
                compression,
                frame_id,
                fragments,
            });
        }
        match node_kind {
            NodeKind::File if symlink_target.is_some() => return Err(Error::CorruptRecord),
            NodeKind::Symlink if symlink_target.is_none() => return Err(Error::CorruptRecord),
            _ => {}
        }
        entries.push(ManifestEntry {
            path,
            len,
            record_offset,
            record_len,
            deleted,
            node_kind,
            permissions,
            symlink_target,
            chunks,
        });
    }
    if offset != payload.len() {
        return Err(Error::CorruptRecord);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_FILE_PERMISSIONS;
    use std::collections::BTreeMap;

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
