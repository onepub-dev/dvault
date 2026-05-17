/// Kind of logical node returned by lockbox listing and stat APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockboxEntryKind {
    /// Regular file content.
    File,
    /// Symbolic link record.
    Symlink,
}

/// Metadata returned by lockbox listing and stat APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockboxEntry {
    /// Canonical logical path inside the lockbox.
    pub path: LockboxPath,
    /// Node kind.
    pub kind: LockboxEntryKind,
    /// File length in bytes, or symlink target length for symlinks.
    pub len: u64,
    /// Stored Unix-style permission bits.
    pub permissions: u32,
    /// Symlink target when `kind` is `LockboxEntryKind::Symlink`.
    pub symlink_target: Option<LockboxPath>,
}
use crate::LockboxPath;
