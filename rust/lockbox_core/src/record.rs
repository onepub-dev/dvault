#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordKind {
    File = 1,
    Delete = 2,
    Manifest = 3,
    Symlink = 4,
    Env = 5,
    EnvDelete = 6,
    FileSegment = 7,
}

impl RecordKind {
    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::File),
            2 => Some(Self::Delete),
            3 => Some(Self::Manifest),
            4 => Some(Self::Symlink),
            5 => Some(Self::Env),
            6 => Some(Self::EnvDelete),
            7 => Some(Self::FileSegment),
            _ => None,
        }
    }
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
