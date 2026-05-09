use crate::constants::{DEFAULT_FILE_PERMISSIONS, DEFAULT_SYMLINK_PERMISSIONS};
use crate::file_chunk::FileChunk;
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::payload::{decode_delete_payloads, decode_file_segment_payload, decode_symlink_payload};
use crate::record::{DecodedRecord, RecordKind};
use crate::Result;

pub(crate) fn decode_index_record(record: &DecodedRecord) -> Result<Option<ManifestEntry>> {
    Ok(decode_index_records(record)?.into_iter().next())
}

pub(crate) fn decode_index_records(record: &DecodedRecord) -> Result<Vec<ManifestEntry>> {
    match record.header.kind {
        RecordKind::FileSegment => {
            let chunks = decode_file_segment_payload(&record.payload)?;
            let mut entries = Vec::new();
            for chunk in chunks {
                entries.push(ManifestEntry {
                    path: chunk.path,
                    len: chunk.total_len,
                    record_offset: record.offset,
                    record_len: record.header.total_len,
                    deleted: false,
                    node_kind: NodeKind::File,
                    permissions: chunk.permissions,
                    symlink_target: None,
                    chunks: vec![FileChunk {
                        record_offset: record.offset,
                        record_len: record.header.total_len,
                        file_offset: chunk.file_offset,
                        len: chunk.data.len() as u64,
                        segment_inner_offset: chunk.segment_inner_offset,
                        segment_inner_len: chunk.data.len() as u64,
                    }],
                });
            }
            Ok(entries)
        }
        RecordKind::Symlink => {
            let (path, target) = decode_symlink_payload(&record.payload)?;
            Ok(vec![ManifestEntry {
                path,
                len: 0,
                record_offset: record.offset,
                record_len: record.header.total_len,
                deleted: false,
                node_kind: NodeKind::Symlink,
                permissions: DEFAULT_SYMLINK_PERMISSIONS,
                symlink_target: Some(target),
                chunks: Vec::new(),
            }])
        }
        RecordKind::Delete => {
            let paths = decode_delete_payloads(&record.payload)?;
            Ok(paths
                .into_iter()
                .map(|path| ManifestEntry {
                    path,
                    len: 0,
                    record_offset: record.offset,
                    record_len: record.header.total_len,
                    deleted: true,
                    node_kind: NodeKind::File,
                    permissions: DEFAULT_FILE_PERMISSIONS,
                    symlink_target: None,
                    chunks: Vec::new(),
                })
                .collect())
        }
        RecordKind::Env
        | RecordKind::EnvDelete
        | RecordKind::TocNode
        | RecordKind::CommitRoot
        | RecordKind::FreeIndex => Ok(Vec::new()),
    }
}
