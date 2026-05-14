use crate::file_chunk::{FileChunk, FileFragment};
use crate::logical_path::validate_stored_path as validate_path;
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
        out.extend_from_slice(&entry.record_object_id.to_le_bytes());
        out.push(entry.deleted as u8);
        out.push(entry.node_kind as u8);
        out.extend_from_slice(&entry.permissions.to_le_bytes());
        out.extend_from_slice(&(entry.chunks.len() as u32).to_le_bytes());
        for chunk in &entry.chunks {
            let stored_path = if chunk.stored_path == entry.path {
                ""
            } else {
                chunk.stored_path.as_str()
            };
            out.extend_from_slice(&(stored_path.len() as u16).to_le_bytes());
            out.extend_from_slice(stored_path.as_bytes());
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
    if count > (payload.len() - 4) / 44 {
        return Err(Error::CorruptRecord);
    }
    let mut offset = 4;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 2 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let path_len = u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if offset + path_len + 42 > payload.len() {
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
        let record_object_id = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let deleted = payload[offset] != 0;
        offset += 1;
        let node_kind = NodeKind::from_u8(payload[offset])?;
        offset += 1;
        let permissions = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        let permissions = validate_permissions(permissions)?;
        offset += 4;
        if offset + 4 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let chunk_count =
            u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if chunk_count > (payload.len() - offset) / 42 {
            return Err(Error::CorruptRecord);
        }
        let mut chunks = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            if offset + 2 > payload.len() {
                return Err(Error::CorruptRecord);
            }
            let stored_path_len =
                u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if offset + stored_path_len + 40 > payload.len() {
                return Err(Error::CorruptRecord);
            }
            let stored_path = if stored_path_len == 0 {
                path.clone()
            } else {
                let stored_path =
                    String::from_utf8(payload[offset..offset + stored_path_len].to_vec())
                        .map_err(|_| Error::CorruptRecord)?;
                validate_path(&stored_path)?;
                stored_path
            };
            offset += stored_path_len;
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
            if fragment_count > (payload.len() - offset) / 40 {
                return Err(Error::CorruptRecord);
            }
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
                stored_path,
                file_offset,
                len: chunk_len,
                compressed_len,
                compression,
                frame_id,
                fragments,
            });
        }
        match node_kind {
            NodeKind::Symlink if record_offset == 0 || record_len == 0 || record_object_id == 0 => {
                return Err(Error::CorruptRecord);
            }
            NodeKind::Symlink if !chunks.is_empty() => return Err(Error::CorruptRecord),
            _ => {}
        }
        entries.push(ManifestEntry {
            path,
            len,
            record_offset,
            record_len,
            record_object_id,
            deleted,
            node_kind,
            permissions,
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
                record_object_id: 1,
                deleted: false,
                node_kind: NodeKind::File,
                permissions: DEFAULT_FILE_PERMISSIONS,
                chunks: Vec::new(),
            },
        );
        let payload = encode_manifest(&manifest);
        assert!(matches!(
            decode_manifest(&payload),
            Err(Error::InvalidPath(_))
        ));
    }

    #[test]
    fn decoded_manifest_rejects_impossible_entry_count_before_allocating() {
        let payload = u32::MAX.to_le_bytes();

        assert!(matches!(
            decode_manifest_entries(&payload),
            Err(Error::CorruptRecord)
        ));
    }

    #[test]
    fn decoded_manifest_rejects_symlink_without_object_reference() {
        let payload = encoded_symlink_entry("/links/current", 0, 0, 0);

        assert!(matches!(
            decode_manifest_entries(&payload),
            Err(Error::CorruptRecord)
        ));
    }

    fn encoded_symlink_entry(
        path: &str,
        record_offset: u64,
        record_len: u64,
        record_object_id: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(path.len() as u16).to_le_bytes());
        out.extend_from_slice(path.as_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&record_offset.to_le_bytes());
        out.extend_from_slice(&record_len.to_le_bytes());
        out.extend_from_slice(&record_object_id.to_le_bytes());
        out.push(0);
        out.push(NodeKind::Symlink as u8);
        out.extend_from_slice(&DEFAULT_FILE_PERMISSIONS.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }
}
