/// Kind of logical node stored in a lockbox listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// Regular file content.
    File,
    /// Symbolic link record.
    Symlink,
}

/// Metadata returned by listing and stat APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Canonical logical path inside the lockbox.
    pub path: String,
    /// Node kind.
    pub kind: EntryKind,
    /// File length in bytes, or symlink target length for symlinks.
    pub len: u64,
    /// Stored Unix-style permission bits.
    pub permissions: u32,
    /// Symlink target when `kind` is `EntryKind::Symlink`.
    pub symlink_target: Option<String>,
    /// Whether this entry represents a deleted historical record.
    pub is_deleted: bool,
}
