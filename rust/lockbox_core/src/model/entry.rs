/// Kind of logical node returned by lockbox listing and stat APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockboxEntryKind {
    /// Regular file content.
    File,
    /// Symbolic link record.
    Symlink,
}

/// Metadata returned by lockbox listing and stat APIs.
///
/// This type contains only metadata stored in the table of contents. Symlink
/// targets are stored in symlink page objects, so callers that need a target
/// should call `Lockbox::get_symlink_target` for symlink entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockboxEntry {
    /// Canonical logical path inside the lockbox.
    pub path: LockboxPath,
    /// Node kind.
    pub kind: LockboxEntryKind,
    /// File length in bytes. Symlink entries report zero.
    pub len: u64,
    /// Stored Unix-style permission bits.
    pub permissions: u32,
}
use crate::LockboxPath;
