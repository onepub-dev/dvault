use crate::file_chunk::FileChunk;
use crate::{Entry, EntryKind};

use crate::node_kind::NodeKind;

#[derive(Debug, Clone)]
pub(crate) struct ManifestEntry {
    pub(crate) path: String,
    pub(crate) len: u64,
    pub(crate) record_offset: u64,
    pub(crate) record_len: u64,
    pub(crate) deleted: bool,
    pub(crate) node_kind: NodeKind,
    pub(crate) permissions: u32,
    pub(crate) symlink_target: Option<String>,
    pub(crate) chunks: Vec<FileChunk>,
}

impl ManifestEntry {
    pub(crate) fn entry_kind(&self) -> EntryKind {
        match self.node_kind {
            NodeKind::File => EntryKind::File,
            NodeKind::Symlink => EntryKind::Symlink,
        }
    }

    pub(crate) fn to_public_entry(&self) -> Entry {
        Entry {
            path: self.path.clone(),
            kind: self.entry_kind(),
            len: self.len,
            permissions: self.permissions,
            symlink_target: self.symlink_target.clone(),
            is_deleted: self.deleted,
        }
    }
}
