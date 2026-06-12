use crate::constants::DEFAULT_SYMLINK_PERMISSIONS;
use crate::file_chunk::{CompressionFrameSegment, FileChunk};
use crate::file_format::decode_compression_frame_segment_payload_view;
use crate::node_kind::NodeKind;
use crate::payload::decode_symlink_payload;
use crate::record::{DecodedRecord, RecordKind};
use crate::toc_entry::TocEntry;
use crate::Result;

pub(crate) fn decode_index_records(record: &DecodedRecord) -> Result<Vec<TocEntry>> {
    match record.header.kind {
        RecordKind::FilePage => {
            let decoded = decode_compression_frame_segment_payload_view(&record.payload)?;
            let Some(manifest) = decoded.manifest.as_ref() else {
                return Ok(Vec::new());
            };
            Ok(manifest
                .slices
                .iter()
                .map(|slice| {
                    let path = slice.path.clone();
                    TocEntry {
                        path: path.clone(),
                        len: slice.total_len,
                        record_offset: record.offset,
                        record_len: record.header.total_len,
                        record_object_id: record.object_id,
                        deleted: false,
                        node_kind: NodeKind::File,
                        permissions: slice.permissions,
                        chunks: vec![FileChunk {
                            stored_path: path,
                            file_offset: slice.file_offset,
                            len: slice.len,
                            compression_frame_offset: slice.compression_frame_offset,
                            compression_frame_len: decoded.compression_frame_len,
                            compressed_len: decoded.compressed_len,
                            compression: decoded.compression,
                            compression_frame_id: decoded.compression_frame_id,
                            compression_frame_digest: decoded.compression_frame_digest,
                            segments: vec![CompressionFrameSegment {
                                page_offset: record.offset,
                                page_len: record.header.total_len,
                                object_id: record.object_id,
                                segment_offset: decoded.segment_offset,
                                segment_len: decoded.data.len() as u64,
                            }],
                        }],
                    }
                })
                .collect())
        }
        RecordKind::Symlink => {
            let (path, _) = decode_symlink_payload(&record.payload)?;
            Ok(vec![TocEntry {
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
        RecordKind::Variable
        | RecordKind::VariableDelete
        | RecordKind::TocNode
        | RecordKind::CommitRoot
        | RecordKind::CommitAuth
        | RecordKind::FreeIndex => Ok(Vec::new()),
    }
}
