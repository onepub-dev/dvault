#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedSymlink {
    pub path: String,
    pub target: String,
}
