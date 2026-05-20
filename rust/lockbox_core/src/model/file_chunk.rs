use std::sync::Arc;

use crate::LockboxPath;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompressionFrameSegment {
    pub(crate) page_offset: u64,
    pub(crate) page_len: u64,
    pub(crate) object_id: u64,
    pub(crate) segment_offset: u64,
    pub(crate) segment_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileChunk {
    pub(crate) stored_path: LockboxPath,
    pub(crate) file_offset: u64,
    pub(crate) len: u64,
    pub(crate) compression_frame_offset: u64,
    pub(crate) compression_frame_len: u64,
    pub(crate) compressed_len: u64,
    pub(crate) compression: u8,
    pub(crate) compression_frame_id: u64,
    pub(crate) compression_frame_digest: [u8; 32],
    pub(crate) segments: Vec<CompressionFrameSegment>,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingFileChunk {
    pub(crate) path: LockboxPath,
    pub(crate) permissions: u32,
    pub(crate) total_len: u64,
    pub(crate) data: Arc<[u8]>,
}
