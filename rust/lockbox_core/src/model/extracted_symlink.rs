/// Symlink metadata returned by in-memory extraction APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedSymlink {
    /// Logical symlink path inside the lockbox.
    pub path: String,
    /// Logical symlink target.
    pub target: String,
}
