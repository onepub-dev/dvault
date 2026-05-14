use crate::constants::DEFAULT_SYMLINK_PERMISSIONS;
use crate::file_chunk::{FileChunk, FileFragment};
use crate::format::decode_file_fragment_payload;
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::payload::decode_symlink_payload;
use crate::record::{DecodedRecord, RecordKind};
use crate::Result;

pub(crate) fn decode_index_record(record: &DecodedRecord) -> Result<Option<ManifestEntry>> {
    Ok(decode_index_records(record)?.into_iter().next())
}

pub(crate) fn decode_index_records(record: &DecodedRecord) -> Result<Vec<ManifestEntry>> {
    match record.header.kind {
        RecordKind::FilePage => {
            let chunk = decode_file_fragment_payload(&record.payload)?;
            let path = chunk.path;
            Ok(vec![ManifestEntry {
                path: path.clone(),
                len: chunk.total_len,
                record_offset: record.offset,
                record_len: record.header.total_len,
                record_object_id: record.object_id,
                deleted: false,
                node_kind: NodeKind::File,
                permissions: chunk.permissions,
                chunks: vec![FileChunk {
                    stored_path: path,
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
            let (path, _) = decode_symlink_payload(&record.payload)?;
            Ok(vec![ManifestEntry {
                path,
                len: 0,
                record_offset: record.offset,
                record_len: record.header.total_len,
                record_object_id: record.object_id,
                deleted: false,
                node_kind: NodeKind::Symlink,
                permissions: DEFAULT_SYMLINK_PERMISSIONS,
                chunks: Vec::new(),
            }])
        }
        RecordKind::Delete => Ok(Vec::new()),
        RecordKind::Env
        | RecordKind::EnvDelete
        | RecordKind::TocNode
        | RecordKind::CommitRoot
        | RecordKind::FreeIndex => Ok(Vec::new()),
    }
}
