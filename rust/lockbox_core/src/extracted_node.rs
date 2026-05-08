use crate::{ExtractedFile, ExtractedSymlink};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractedNode {
    File(ExtractedFile),
    Symlink(ExtractedSymlink),
}
