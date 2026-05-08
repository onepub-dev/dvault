use std::collections::BTreeMap;

use super::Lockbox;
use crate::format::{
    decode_file_payload, decode_index_record, decode_index_records, decode_manifest,
    decode_symlink_payload, read_header, read_record, scan_records,
};
use crate::node_kind::NodeKind;
use crate::record::RecordKind;
use crate::{Entry, RecoveryReport, Result};

impl Lockbox {
    pub fn recover(bytes: Vec<u8>, key: impl AsRef<[u8]>) -> RecoveryReport {
        let key = key.as_ref().to_vec();
        let scan = scan_records(&bytes, &key);
        let mut manifest = BTreeMap::new();
        let mut corrupt_records = scan.corrupt_records;
        let mut manifest_recovered = false;

        if let Ok((manifest_offset, _, _, _)) = read_header(&bytes) {
            if manifest_offset > 0 {
                if let Ok(record) = read_record(&bytes, manifest_offset, &key) {
                    if record.header.kind == RecordKind::Manifest {
                        if let Ok(decoded) = decode_manifest(&record.payload) {
                            manifest = decoded;
                            manifest_recovered = true;
                        }
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
            let complete = read_record(&bytes, entry.record_offset, &key)
                .ok()
                .filter(|r| {
                    matches!(
                        (entry.node_kind, r.header.kind),
                        (NodeKind::File, RecordKind::File)
                            | (NodeKind::File, RecordKind::FileSegment)
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
        let scan = scan_records(&bytes, &key_bytes);
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
            if let Ok(record) = read_record(&bytes, entry.record_offset, &key_bytes) {
                match record.header.kind {
                    RecordKind::File => {
                        if let Ok((path, permissions, file_bytes)) =
                            decode_file_payload(&record.payload)
                        {
                            recovered.put_file_with_permissions(&path, &file_bytes, permissions)?;
                        }
                    }
                    RecordKind::FileSegment => {
                        if let Ok(file_bytes) = read_segment_file_bytes(&bytes, entry, &key_bytes) {
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
        Self::recover(self.bytes.clone(), self.key.expose())
    }
}

fn read_segment_file_bytes(
    bytes: &[u8],
    entry: &crate::manifest_entry::ManifestEntry,
    key: &[u8],
) -> Result<Vec<u8>> {
    let mut chunks = entry.chunks.clone();
    chunks.sort_by_key(|chunk| chunk.file_offset);
    let mut out = Vec::with_capacity(entry.len as usize);
    for chunk in chunks {
        let record = read_record(bytes, chunk.record_offset, key)?;
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
