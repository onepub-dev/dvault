use std::collections::BTreeMap;
use std::path::Path;

use super::Lockbox;
use crate::constants::DEFAULT_MAX_FILE_BYTES;
use crate::file_format::{
    decode_index_record, decode_index_records, decode_symlink_payload, decode_toc_node, read_header,
};
use crate::lockbox_id::LockboxId;
use crate::node_kind::NodeKind;
use crate::page_scanner::PageScanner;
use crate::record::RecordKind;
use crate::toc_entry::TocEntry;
use crate::{Error, LockboxEntry, LockboxPath, RecoveryReport, Result};

/// Scans damaged lockbox storage and reports or salvages recoverable content.
///
/// Recovery is intentionally separated from `Lockbox` because it operates on
/// storage bytes and can succeed when a normal open fails.
pub struct RecoveryScanner;

impl RecoveryScanner {
    /// Scan a lockbox file from disk and report recoverable entries.
    pub fn scan_path(path: &Path, key: impl AsRef<[u8]>) -> RecoveryReport {
        match std::fs::read(path) {
            Ok(bytes) => Self::scan_bytes(bytes, key),
            Err(_) => RecoveryReport {
                intact_files: Vec::new(),
                intact_file_count: 0,
                partial_files: 0,
                corrupt_records: 1,
                toc_recovered: false,
            },
        }
    }

    /// Scan lockbox storage bytes and report recoverable entries.
    pub fn scan_bytes(bytes: Vec<u8>, key: impl AsRef<[u8]>) -> RecoveryReport {
        recover_bytes(bytes, key)
    }

    /// Salvage a damaged lockbox from storage bytes into a new opened lockbox.
    ///
    /// Returns `Error::InvalidKey` if the supplied key cannot authenticate any
    /// recoverable records, or `Error::CorruptRecord`/storage errors if the
    /// recovered content cannot be written into the new lockbox.
    pub fn salvage_bytes(bytes: Vec<u8>, key: impl AsRef<[u8]>) -> Result<Lockbox> {
        salvage_bytes(bytes, key)
    }
}

fn recover_bytes(bytes: Vec<u8>, key: impl AsRef<[u8]>) -> RecoveryReport {
    let key = key.as_ref().to_vec();
    let lockbox_id = lockbox_id_from_bytes_unchecked(&bytes);
    let scanner = PageScanner::new(&bytes, lockbox_id, &key);
    let scan = scanner.scan_records();
    let mut toc_entries = BTreeMap::new();
    let mut corrupt_records = scan.corrupt_records;
    let mut toc_recovered = false;

    if let Ok((root_offset, _, _, _)) = read_header(&bytes) {
        if root_offset > 0 {
            if let Ok(commit_root) = scanner.commit_root_at(root_offset) {
                if let Ok(decoded) =
                    decode_toc_btree_from_offset(&scanner, commit_root.toc_root_offset, 0)
                {
                    toc_entries = decoded;
                    toc_recovered = true;
                }
            }
        }
    }

    if toc_entries.is_empty() {
        for record in scan.records {
            match decode_index_records(&record) {
                Ok(entries) => {
                    for entry in entries {
                        apply_scanned_entry(&mut toc_entries, entry);
                    }
                }
                Err(_) => corrupt_records += 1,
            }
        }
    }

    let mut intact_files = Vec::new();
    let mut intact_file_count = 0;
    let mut partial_files = 0;

    for entry in toc_entries.values() {
        if entry.deleted {
            continue;
        }
        let complete = match entry.node_kind {
            NodeKind::File => read_page_file_bytes(&scanner, entry).is_ok(),
            NodeKind::Symlink => recover_symlink_target(&scanner, entry).is_ok(),
        };
        if complete {
            intact_file_count += 1;
        } else {
            partial_files += 1;
        }
        intact_files.push(LockboxEntry {
            path: entry.path.clone(),
            kind: entry.entry_kind(),
            len: entry.len,
            permissions: entry.permissions,
        });
    }

    RecoveryReport {
        intact_files,
        intact_file_count,
        partial_files,
        corrupt_records,
        toc_recovered,
    }
}

fn salvage_bytes(bytes: Vec<u8>, key: impl AsRef<[u8]>) -> Result<Lockbox> {
    let key_bytes = key.as_ref().to_vec();
    let lockbox_id = lockbox_id_from_bytes_unchecked(&bytes);
    let scanner = PageScanner::new(&bytes, lockbox_id, &key_bytes);
    let scan = scanner.scan_records();
    let mut recovered = Lockbox::create_with_secret_key_and_options(
        crate::SecretVec::try_from_slice(&key_bytes)?,
        lockbox_id,
        crate::LockboxOptions::default(),
    );
    let mut latest_paths = BTreeMap::new();

    for record in scan.records {
        if let Ok(Some(entry)) = decode_index_record(&record) {
            apply_scanned_entry(&mut latest_paths, entry);
        }
    }

    for entry in latest_paths.values() {
        if entry.deleted {
            continue;
        }
        let record = if entry.record_object_id == 0 {
            scanner.record_at(entry.record_offset)
        } else {
            scanner.record_object_at(entry.record_offset, entry.record_object_id)
        };
        if let Ok(record) = record {
            match record.header.kind {
                RecordKind::FilePage => {
                    if let Ok(file_bytes) = read_page_file_bytes(&scanner, entry) {
                        recovered.add_file_with_permissions(
                            &entry.path,
                            &file_bytes,
                            entry.permissions,
                            false,
                        )?;
                    }
                }
                RecordKind::Symlink => {
                    if let Ok((path, target)) = decode_symlink_payload(&record.payload) {
                        recovered.add_symlink(&path, &target, false)?;
                    }
                }
                _ => {}
            }
        }
    }
    recovered.commit()?;
    Ok(recovered)
}

fn decode_toc_btree_from_offset(
    scanner: &PageScanner<'_>,
    offset: u64,
    depth: usize,
) -> Result<BTreeMap<LockboxPath, TocEntry>> {
    if depth > 8 {
        return Err(crate::Error::CorruptRecord);
    }
    let payload = scanner.toc_node_payload_at(offset)?;

    let mut toc_entries = BTreeMap::new();
    match decode_toc_node(&payload)? {
        crate::file_format::TocNode::Leaf(entries) => {
            for entry in entries {
                toc_entries.insert(entry.path.clone(), entry);
            }
        }
        crate::file_format::TocNode::Internal(children) => {
            for child in children {
                let child_toc_entries =
                    decode_toc_btree_from_offset(scanner, child.offset, depth + 1)?;
                toc_entries.extend(child_toc_entries);
            }
        }
    }
    Ok(toc_entries)
}

fn read_page_file_bytes(
    scanner: &PageScanner<'_>,
    entry: &crate::toc_entry::TocEntry,
) -> Result<Vec<u8>> {
    let mut chunks = entry.chunks.clone();
    chunks.sort_by_key(|chunk| chunk.file_offset);
    let expected_len = if entry.len == 0 && chunks.iter().any(|chunk| chunk.len > 0) {
        chunks.iter().try_fold(0u64, |max_end, chunk| {
            let end = chunk
                .file_offset
                .checked_add(chunk.len)
                .ok_or(Error::CorruptRecord)?;
            Ok::<u64, Error>(max_end.max(end))
        })?
    } else {
        entry.len
    };
    if expected_len > DEFAULT_MAX_FILE_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "recovered file exceeds default safety limit".to_string(),
        ));
    }
    let capacity = usize::try_from(expected_len).map_err(|_| Error::CorruptRecord)?;
    let mut out = Vec::with_capacity(capacity);
    for chunk in chunks {
        if chunk.compressed_len > crate::constants::DEFAULT_MAX_PAGE_LOGICAL_BYTES as u64 {
            return Err(Error::SecurityLimitExceeded(
                "compressed file frame exceeds safety limit".to_string(),
            ));
        }
        if chunk.file_offset != out.len() as u64 {
            return Err(Error::CorruptRecord);
        }
        let compressed_len =
            usize::try_from(chunk.compressed_len).map_err(|_| Error::CorruptRecord)?;
        let mut stored = vec![0u8; compressed_len];
        for fragment in &chunk.fragments {
            let decoded = scanner.file_fragment_at(fragment.page_offset, fragment.object_id)?;
            if decoded.path != chunk.stored_path
                || (decoded.total_len != 0 && decoded.total_len != expected_len)
                || decoded.file_offset != chunk.file_offset
                || decoded.len != chunk.len
                || decoded.compressed_len != chunk.compressed_len
                || decoded.compression != chunk.compression
                || decoded.frame_id != chunk.frame_id
                || decoded.fragment_offset != fragment.fragment_offset
                || decoded.data.len() as u64 != fragment.fragment_len
            {
                return Err(Error::CorruptRecord);
            }
            let start =
                usize::try_from(fragment.fragment_offset).map_err(|_| Error::CorruptRecord)?;
            let end = start
                .checked_add(decoded.data.len())
                .ok_or(Error::CorruptRecord)?;
            if end > stored.len() {
                return Err(Error::CorruptRecord);
            }
            stored[start..end].copy_from_slice(&decoded.data);
        }
        let decoded = crate::compression::decode_file_frame(chunk.compression, &stored, chunk.len)?;
        out.extend_from_slice(&decoded);
        if out.len() as u64 > expected_len {
            return Err(Error::CorruptRecord);
        }
    }
    if out.len() as u64 != expected_len {
        return Err(Error::CorruptRecord);
    }
    Ok(out)
}

fn recover_symlink_target(scanner: &PageScanner<'_>, entry: &TocEntry) -> Result<LockboxPath> {
    if entry.record_offset == 0 || entry.record_object_id == 0 {
        return Err(Error::CorruptRecord);
    }
    let record = scanner.record_object_at(entry.record_offset, entry.record_object_id)?;
    if record.header.kind != RecordKind::Symlink {
        return Err(Error::CorruptRecord);
    }
    let (path, target) = decode_symlink_payload(&record.payload)?;
    if path != entry.path {
        return Err(Error::CorruptRecord);
    }
    Ok(target)
}

fn apply_scanned_entry(toc_entries: &mut BTreeMap<LockboxPath, TocEntry>, mut entry: TocEntry) {
    if entry.deleted || entry.node_kind != NodeKind::File {
        toc_entries.insert(entry.path.clone(), entry);
        return;
    }
    if entry.len == 0 {
        entry.len = recovered_len_from_chunks(&entry).unwrap_or(0);
    }
    toc_entries
        .entry(entry.path.clone())
        .and_modify(|existing| {
            if existing.deleted || existing.node_kind != NodeKind::File {
                *existing = entry.clone();
                return;
            }
            existing.len = existing.len.max(entry.len);
            existing.record_offset = existing.record_offset.min(entry.record_offset);
            existing.record_len = existing.record_len.max(entry.record_len);
            existing.chunks.extend(entry.chunks.clone());
        })
        .or_insert(entry);
}

fn recovered_len_from_chunks(entry: &TocEntry) -> Result<u64> {
    entry.chunks.iter().try_fold(0u64, |max_end, chunk| {
        let end = chunk
            .file_offset
            .checked_add(chunk.len)
            .ok_or(Error::CorruptRecord)?;
        Ok(max_end.max(end))
    })
}

fn lockbox_id_from_bytes_unchecked(bytes: &[u8]) -> LockboxId {
    bytes
        .get(40..56)
        .and_then(|bytes| bytes.try_into().ok())
        .map(LockboxId::from_bytes)
        .unwrap_or_else(|| LockboxId::from_bytes([0; 16]))
}
