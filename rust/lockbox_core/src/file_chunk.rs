#[derive(Debug, Clone)]
pub(crate) struct FileChunk {
    pub(crate) record_offset: u64,
    pub(crate) record_len: u64,
    pub(crate) file_offset: u64,
    pub(crate) len: u64,
    pub(crate) segment_inner_offset: u64,
    pub(crate) segment_inner_len: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingFileChunk {
    pub(crate) path: String,
    pub(crate) permissions: u32,
    pub(crate) total_len: u64,
    pub(crate) file_offset: u64,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct DecodedFileChunk {
    pub(crate) path: String,
    pub(crate) permissions: u32,
    pub(crate) total_len: u64,
    pub(crate) file_offset: u64,
    pub(crate) segment_inner_offset: u64,
    pub(crate) data: Vec<u8>,
}
