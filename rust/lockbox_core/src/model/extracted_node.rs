use crate::{ExtractedFile, ExtractedSymlink};

/// Node returned by extraction APIs that include both files and symlinks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractedNode {
    /// Extracted regular file.
    File(ExtractedFile),
    /// Extracted symlink metadata.
    Symlink(ExtractedSymlink),
}
