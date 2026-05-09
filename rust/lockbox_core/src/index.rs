use crate::constants::{DEFAULT_FILE_PERMISSIONS, DEFAULT_SYMLINK_PERMISSIONS};
use crate::file_chunk::{FileChunk, FileFragment};
use crate::format::decode_file_fragment_payload;
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::payload::{decode_delete_payloads, decode_symlink_payload};
use crate::record::{DecodedRecord, RecordKind};
use crate::Result;

pub(crate) fn decode_index_record(record: &DecodedRecord) -> Result<Option<ManifestEntry>> {
    Ok(decode_index_records(record)?.into_iter().next())
}

pub(crate) fn decode_index_records(record: &DecodedRecord) -> Result<Vec<ManifestEntry>> {
    match record.header.kind {
        RecordKind::FileSegment => {
            let chunk = decode_file_fragment_payload(&record.payload)?;
            Ok(vec![ManifestEntry {
                path: chunk.path,
                len: chunk.total_len,
                record_offset: record.offset,
                record_len: record.header.total_len,
                deleted: false,
                node_kind: NodeKind::File,
                permissions: chunk.permissions,
                symlink_target: None,
                chunks: vec![FileChunk {
                    file_offset: chunk.file_offset,
                    len: chunk.len,
                    compressed_len: chunk.compressed_len,
                    compression: chunk.compression,
                    frame_id: chunk.frame_id,
                    fragments: vec![FileFragment {
                        page_offset: record.offset,
                        page_len: record.header.total_len,
                        object_id: record.object_id,
                        fragment_offset: chunk.fragment_offset,
                        fragment_len: chunk.data.len() as u64,
                    }],
                }],
            }])
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
