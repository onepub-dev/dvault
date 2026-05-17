use crate::file_chunk::FileChunk;
use crate::{LockboxEntry, LockboxEntryKind, LockboxPath};

use crate::node_kind::NodeKind;

#[derive(Debug, Clone)]
pub(crate) struct TocEntry {
    pub(crate) path: LockboxPath,
    pub(crate) len: u64,
    pub(crate) record_offset: u64,
    pub(crate) record_len: u64,
    pub(crate) record_object_id: u64,
    pub(crate) deleted: bool,
    pub(crate) node_kind: NodeKind,
    pub(crate) permissions: u32,
    pub(crate) chunks: Vec<FileChunk>,
}

impl TocEntry {
    pub(crate) fn entry_kind(&self) -> LockboxEntryKind {
        match self.node_kind {
            NodeKind::File => LockboxEntryKind::File,
            NodeKind::Symlink => LockboxEntryKind::Symlink,
        }
    }

    pub(crate) fn to_public_entry(&self) -> LockboxEntry {
        LockboxEntry {
            path: self.path.clone(),
            kind: self.entry_kind(),
            len: self.len,
            permissions: self.permissions,
        }
    }
}
