use std::collections::BTreeMap;
use std::path::Path;

use super::Lockbox;
use crate::commit_root::decode_commit_root;
use crate::format::{
    decode_index_record, decode_index_records, decode_symlink_payload, decode_toc_node, read_header,
};
use crate::lockbox_id::LockboxId;
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::page::{decode_page, scan_page_records, PageObjectKind, DEFAULT_PAGE_BYTES, PAGE_MAGIC};
use crate::record::{DecodedRecord, RecordKind};
use crate::{Entry, RecoveryReport, Result};

impl Lockbox {
    pub fn recover_path(path: impl AsRef<Path>, key: impl AsRef<[u8]>) -> RecoveryReport {
        match std::fs::read(path.as_ref()) {
            Ok(bytes) => Self::recover(bytes, key),
            Err(_) => RecoveryReport {
                intact_files: Vec::new(),
                intact_file_count: 0,
                partial_files: 0,
                corrupt_records: 1,
                manifest_recovered: false,
            },
        }
    }

    pub fn recover(bytes: Vec<u8>, key: impl AsRef<[u8]>) -> RecoveryReport {
        let key = key.as_ref().to_vec();
        let lockbox_id = lockbox_id_from_bytes_unchecked(&bytes);
        let scan = scan_page_records(&bytes, lockbox_id, &key);
        let mut manifest = BTreeMap::new();
        let mut corrupt_records = scan.corrupt_records;
        let mut manifest_recovered = false;

        if let Ok((root_offset, _, _, _)) = read_header(&bytes) {
            if root_offset > 0 {
                let toc_root = bytes
                    .get(root_offset as usize..root_offset as usize + DEFAULT_PAGE_BYTES)
                    .filter(|page| page.get(..8) == Some(PAGE_MAGIC.as_slice()))
                    .ok_or(crate::Error::CorruptRecord)
                    .and_then(|page| {
                        let decoded = decode_page(page, lockbox_id, &key)?;
                        let Some(commit_root_object) = decoded
                            .objects
                            .iter()
                            .find(|object| object.kind == PageObjectKind::CommitRoot)
                        else {
                            return Err(crate::Error::CorruptRecord);
                        };
                        decode_commit_root(&commit_root_object.payload)
                    });
                if let Ok(commit_root) = toc_root {
                    if let Ok(decoded) = decode_toc_btree_from_offset(
                        &bytes,
                        &key,
                        lockbox_id,
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
            let complete = match entry.node_kind {
                NodeKind::File => read_page_file_bytes(&bytes, entry, &key, lockbox_id).is_ok(),
                NodeKind::Symlink => {
                    read_record_from_page(&bytes, &key, lockbox_id, entry.record_offset)
                        .ok()
                        .filter(|r| r.header.kind == RecordKind::Symlink)
                        .is_some()
                }
            };
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
        let lockbox_id = lockbox_id_from_bytes_unchecked(&bytes);
        let scan = scan_page_records(&bytes, lockbox_id, &key_bytes);
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
                read_record_from_page(&bytes, &key_bytes, lockbox_id, entry.record_offset)
            {
                match record.header.kind {
                    RecordKind::FilePage => {
                        if let Ok(file_bytes) =
                            read_page_file_bytes(&bytes, entry, &key_bytes, lockbox_id)
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
    lockbox_id: crate::LockboxId,
    offset: u64,
    depth: usize,
) -> Result<BTreeMap<String, ManifestEntry>> {
    if depth > 8 {
        return Err(crate::Error::CorruptRecord);
    }
    let payload = read_toc_node_payload_from_bytes(bytes, key, lockbox_id, offset)?;

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
                    decode_toc_btree_from_offset(bytes, key, lockbox_id, child.offset, depth + 1)?;
                manifest.extend(child_manifest);
            }
        }
    }
    Ok(manifest)
}

fn read_toc_node_payload_from_bytes(
    bytes: &[u8],
    key: &[u8],
    lockbox_id: crate::LockboxId,
    offset: u64,
) -> Result<Vec<u8>> {
    if bytes.get(offset as usize..offset as usize + 8) == Some(PAGE_MAGIC.as_slice()) {
        let page = bytes
            .get(offset as usize..offset as usize + DEFAULT_PAGE_BYTES)
            .ok_or(crate::Error::Truncated)?;
        let decoded = decode_page(page, lockbox_id, key)?;
        let Some(toc_object) = decoded.objects.iter().find(|object| {
            matches!(
                object.kind,
                PageObjectKind::TocLeaf | PageObjectKind::TocInternal
            )
        }) else {
            return Err(crate::Error::CorruptRecord);
        };
        return Ok(toc_object.payload.clone());
    }
    Err(crate::Error::CorruptRecord)
}

fn read_page_file_bytes(
    bytes: &[u8],
    entry: &crate::manifest_entry::ManifestEntry,
    key: &[u8],
    lockbox_id: LockboxId,
) -> Result<Vec<u8>> {
    let mut chunks = entry.chunks.clone();
    chunks.sort_by_key(|chunk| chunk.file_offset);
    let mut out = Vec::with_capacity(entry.len as usize);
    for chunk in chunks {
        let mut stored = vec![0u8; chunk.compressed_len as usize];
        for fragment in &chunk.fragments {
            let page = bytes
                .get(
                    fragment.page_offset as usize
                        ..fragment.page_offset as usize + DEFAULT_PAGE_BYTES,
                )
                .ok_or(crate::Error::Truncated)?;
            let decoded_page = decode_page(page, lockbox_id, key)?;
            let Some(object) = decoded_page
                .objects
                .iter()
                .find(|object| object.id == fragment.object_id)
            else {
                return Err(crate::Error::CorruptRecord);
            };
            let decoded = crate::format::decode_file_fragment_payload(&object.payload)?;
            if decoded.path != entry.path
                || (decoded.total_len != 0 && decoded.total_len != entry.len)
                || decoded.file_offset != chunk.file_offset
                || decoded.len != chunk.len
                || decoded.compressed_len != chunk.compressed_len
                || decoded.compression != chunk.compression
                || decoded.frame_id != chunk.frame_id
                || decoded.fragment_offset != fragment.fragment_offset
                || decoded.data.len() as u64 != fragment.fragment_len
            {
                return Err(crate::Error::CorruptRecord);
            }
            let start = usize::try_from(fragment.fragment_offset)
                .map_err(|_| crate::Error::CorruptRecord)?;
            let end = start
                .checked_add(decoded.data.len())
                .ok_or(crate::Error::CorruptRecord)?;
            if end > stored.len() {
                return Err(crate::Error::CorruptRecord);
            }
            stored[start..end].copy_from_slice(&decoded.data);
        }
        let decoded = crate::compression::decode_file_frame(chunk.compression, &stored, chunk.len)?;
        out.extend_from_slice(&decoded);
    }
    Ok(out)
}

fn read_record_from_page(
    bytes: &[u8],
    key: &[u8],
    lockbox_id: LockboxId,
    offset: u64,
) -> Result<DecodedRecord> {
    let page = bytes
        .get(offset as usize..offset as usize + DEFAULT_PAGE_BYTES)
        .ok_or(crate::Error::Truncated)?;
    let decoded = decode_page(page, lockbox_id, key)?;
    let Some(object) = decoded.objects.first() else {
        return Err(crate::Error::CorruptRecord);
    };
    let kind = match object.kind {
        PageObjectKind::PackedFileData | PageObjectKind::FileData => RecordKind::FilePage,
        PageObjectKind::Symlink => RecordKind::Symlink,
        PageObjectKind::EnvSet => RecordKind::Env,
        PageObjectKind::EnvDelete => RecordKind::EnvDelete,
        PageObjectKind::Delete => RecordKind::Delete,
        PageObjectKind::TocLeaf | PageObjectKind::TocInternal => RecordKind::TocNode,
        PageObjectKind::CommitRoot => RecordKind::CommitRoot,
        PageObjectKind::FreeIndexLeaf | PageObjectKind::FreeIndexInternal => RecordKind::FreeIndex,
        PageObjectKind::KeyDirectory => return Err(crate::Error::CorruptRecord),
    };
    Ok(DecodedRecord {
        header: crate::record::RecordHeader {
            kind,
            sequence: decoded.sequence,
            total_len: DEFAULT_PAGE_BYTES as u64,
        },
        offset,
        object_id: object.id,
        payload: object.payload.clone(),
    })
}

fn lockbox_id_from_bytes_unchecked(bytes: &[u8]) -> LockboxId {
    bytes
        .get(40..56)
        .and_then(|bytes| bytes.try_into().ok())
        .map(LockboxId::from_bytes)
        .unwrap_or_else(|| LockboxId::from_bytes([0; 16]))
}
