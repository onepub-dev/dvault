#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordKind {
    Delete = 2,
    Symlink = 4,
    Env = 5,
    EnvDelete = 6,
    FileSegment = 7,
    TocNode = 8,
    CommitRoot = 9,
    FreeIndex = 10,
}

#[derive(Debug, Clone)]
pub(crate) struct RecordHeader {
    pub(crate) kind: RecordKind,
    pub(crate) sequence: u64,
    pub(crate) total_len: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct DecodedRecord {
    pub(crate) header: RecordHeader,
    pub(crate) offset: u64,
    pub(crate) payload: Vec<u8>,
}
