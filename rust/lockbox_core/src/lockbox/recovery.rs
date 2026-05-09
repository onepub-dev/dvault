use std::collections::BTreeMap;

use super::Lockbox;
use crate::commit_root::decode_commit_root;
use crate::format::{
    decode_index_record, decode_index_records, decode_symlink_payload, decode_toc_node, read_header,
};
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::record::{DecodedRecord, RecordKind};
use crate::segment_page::{
    decode_segment_page, scan_segment_page_records, SegmentObjectKind, DEFAULT_SEGMENT_PAGE_BYTES,
    SEGMENT_PAGE_MAGIC,
};
use crate::vault_id::VaultId;
use crate::{Entry, RecoveryReport, Result};

impl Lockbox {
    pub fn recover(bytes: Vec<u8>, key: impl AsRef<[u8]>) -> RecoveryReport {
        let key = key.as_ref().to_vec();
        let vault_id = vault_id_from_bytes_unchecked(&bytes);
        let scan = scan_segment_page_records(&bytes, vault_id, &key);
        let mut manifest = BTreeMap::new();
        let mut corrupt_records = scan.corrupt_records;
        let mut manifest_recovered = false;

        if let Ok((root_offset, _, _, _)) = read_header(&bytes) {
            if root_offset > 0 {
                let toc_root = bytes
                    .get(root_offset as usize..root_offset as usize + DEFAULT_SEGMENT_PAGE_BYTES)
                    .filter(|page| page.get(..8) == Some(SEGMENT_PAGE_MAGIC.as_slice()))
                    .ok_or(crate::Error::CorruptRecord)
                    .and_then(|page| {
                        let decoded = decode_segment_page(page, vault_id, &key)?;
                        let Some(commit_root_object) = decoded
                            .objects
                            .iter()
                            .find(|object| object.kind == SegmentObjectKind::CommitRoot)
                        else {
                            return Err(crate::Error::CorruptRecord);
                        };
                        decode_commit_root(&commit_root_object.payload)
                    });
                if let Ok(commit_root) = toc_root {
                    if let Ok(decoded) = decode_toc_btree_from_offset(
                        &bytes,
                        &key,
                        vault_id,
                        commit_root.toc_root_offset,
                        0,
                    ) {
                        manifest = decoded;
                        manifest_recovered = true;
                    }
                }
            }
        }

        if manifest.is_empty() {
            for record in scan.records {
                match decode_index_records(&record) {
                    Ok(entries) => {
                        for entry in entries {
                            manifest.insert(entry.path.clone(), entry);
                        }
                    }
                    Err(_) => corrupt_records += 1,
                }
            }
        }

        let mut intact_files = Vec::new();
        let mut intact_file_count = 0;
        let mut partial_files = 0;

        for entry in manifest.values() {
            if entry.deleted {
                continue;
            }
            let complete = read_record_from_page(&bytes, &key, vault_id, entry.record_offset)
                .ok()
                .filter(|r| {
                    matches!(
                        (entry.node_kind, r.header.kind),
                        (NodeKind::File, RecordKind::FileSegment)
                            | (NodeKind::Symlink, RecordKind::Symlink)
                    )
                })
                .is_some();
            if complete {
                intact_file_count += 1;
            } else {
                partial_files += 1;
            }
            intact_files.push(Entry {
                path: entry.path.clone(),
                kind: entry.entry_kind(),
                len: entry.len,
                permissions: entry.permissions,
                symlink_target: entry.symlink_target.clone(),
                is_deleted: false,
            });
        }

        RecoveryReport {
            intact_files,
            intact_file_count,
            partial_files,
            corrupt_records,
            manifest_recovered,
        }
    }

    pub fn salvage(bytes: Vec<u8>, key: impl AsRef<[u8]>) -> Result<Self> {
        let key_bytes = key.as_ref().to_vec();
        let vault_id = vault_id_from_bytes_unchecked(&bytes);
        let scan = scan_segment_page_records(&bytes, vault_id, &key_bytes);
        let mut recovered = Self::create(&key_bytes);
        let mut latest_paths = BTreeMap::new();

        for record in scan.records {
            if let Ok(Some(entry)) = decode_index_record(&record) {
                latest_paths.insert(entry.path.clone(), entry);
            }
        }

        for entry in latest_paths.values() {
            if entry.deleted {
                continue;
            }
            if let Ok(record) =
                read_record_from_page(&bytes, &key_bytes, vault_id, entry.record_offset)
            {
                match record.header.kind {
                    RecordKind::FileSegment => {
                        if let Ok(file_bytes) =
                            read_segment_file_bytes(&bytes, entry, &key_bytes, vault_id)
                        {
                            recovered.put_file_with_permissions(
                                &entry.path,
                                &file_bytes,
                                entry.permissions,
                            )?;
                        }
                    }
                    RecordKind::Symlink => {
                        if let Ok((path, target)) = decode_symlink_payload(&record.payload) {
                            recovered.put_symlink(&path, &target)?;
                        }
                    }
                    _ => {}
                }
            }
        }
        recovered.commit()?;
        Ok(recovered)
    }

    pub fn recover_current(&self) -> RecoveryReport {
        match self.bytes() {
            Ok(bytes) => Self::recover(bytes, self.key.expose()),
            Err(_err) => RecoveryReport {
                intact_files: Vec::new(),
                intact_file_count: 0,
                partial_files: 0,
                corrupt_records: 1,
                manifest_recovered: false,
            },
        }
    }
}

fn decode_toc_btree_from_offset(
    bytes: &[u8],
    key: &[u8],
    vault_id: crate::VaultId,
    offset: u64,
    depth: usize,
) -> Result<BTreeMap<String, ManifestEntry>> {
    if depth > 8 {
        return Err(crate::Error::CorruptRecord);
    }
    let payload = read_toc_node_payload_from_bytes(bytes, key, vault_id, offset)?;

    let mut manifest = BTreeMap::new();
    match decode_toc_node(&payload)? {
        crate::format::TocNode::Leaf(entries) => {
            for entry in entries {
                manifest.insert(entry.path.clone(), entry);
            }
        }
        crate::format::TocNode::Internal(children) => {
            for child in children {
                let child_manifest =
                    decode_toc_btree_from_offset(bytes, key, vault_id, child.offset, depth + 1)?;
                manifest.extend(child_manifest);
            }
        }
    }
    Ok(manifest)
}

fn read_toc_node_payload_from_bytes(
    bytes: &[u8],
    key: &[u8],
    vault_id: crate::VaultId,
    offset: u64,
) -> Result<Vec<u8>> {
    if bytes.get(offset as usize..offset as usize + 8) == Some(SEGMENT_PAGE_MAGIC.as_slice()) {
        let page = bytes
            .get(offset as usize..offset as usize + DEFAULT_SEGMENT_PAGE_BYTES)
            .ok_or(crate::Error::Truncated)?;
        let decoded = decode_segment_page(page, vault_id, key)?;
        let Some(toc_object) = decoded.objects.iter().find(|object| {
            matches!(
                object.kind,
                SegmentObjectKind::TocLeaf | SegmentObjectKind::TocInternal
            )
        }) else {
            return Err(crate::Error::CorruptRecord);
        };
        return Ok(toc_object.payload.clone());
    }
    Err(crate::Error::CorruptRecord)
}

fn read_segment_file_bytes(
    bytes: &[u8],
    entry: &crate::manifest_entry::ManifestEntry,
    key: &[u8],
    vault_id: VaultId,
) -> Result<Vec<u8>> {
    let mut chunks = entry.chunks.clone();
    chunks.sort_by_key(|chunk| chunk.file_offset);
    let mut out = Vec::with_capacity(entry.len as usize);
    for chunk in chunks {
        let record = read_record_from_page(bytes, key, vault_id, chunk.record_offset)?;
        let decoded = crate::payload::decode_file_segment_payload(&record.payload)?;
        let Some(decoded_chunk) = decoded
            .into_iter()
            .find(|item| item.path == entry.path && item.file_offset == chunk.file_offset)
        else {
            return Err(crate::Error::CorruptRecord);
        };
        out.extend_from_slice(&decoded_chunk.data);
    }
    Ok(out)
}

fn read_record_from_page(
    bytes: &[u8],
    key: &[u8],
    vault_id: VaultId,
    offset: u64,
) -> Result<DecodedRecord> {
    let page = bytes
        .get(offset as usize..offset as usize + DEFAULT_SEGMENT_PAGE_BYTES)
        .ok_or(crate::Error::Truncated)?;
    let decoded = decode_segment_page(page, vault_id, key)?;
    let Some(object) = decoded.objects.first() else {
        return Err(crate::Error::CorruptRecord);
    };
    let kind = match object.kind {
        SegmentObjectKind::PackedFileData | SegmentObjectKind::FileData => RecordKind::FileSegment,
        SegmentObjectKind::Symlink => RecordKind::Symlink,
        SegmentObjectKind::EnvSet => RecordKind::Env,
        SegmentObjectKind::EnvDelete => RecordKind::EnvDelete,
        SegmentObjectKind::Delete => RecordKind::Delete,
        SegmentObjectKind::TocLeaf | SegmentObjectKind::TocInternal => RecordKind::TocNode,
        SegmentObjectKind::CommitRoot => RecordKind::CommitRoot,
        SegmentObjectKind::FreeIndexLeaf | SegmentObjectKind::FreeIndexInternal => {
            RecordKind::FreeIndex
        }
        SegmentObjectKind::KeyDirectory => return Err(crate::Error::CorruptRecord),
    };
    Ok(DecodedRecord {
        header: crate::record::RecordHeader {
            kind,
            sequence: decoded.sequence,
            total_len: DEFAULT_SEGMENT_PAGE_BYTES as u64,
        },
        offset,
        payload: object.payload.clone(),
    })
}

fn vault_id_from_bytes_unchecked(bytes: &[u8]) -> VaultId {
    bytes
        .get(40..56)
        .and_then(|bytes| bytes.try_into().ok())
        .map(VaultId::from_bytes)
        .unwrap_or_else(|| VaultId::from_bytes([0; 16]))
}
