/// Options for listing lockbox entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListOptions {
    /// Root logical path to list from.
    pub path: String,
    /// Optional glob applied to returned logical paths.
    pub glob: Option<String>,
    /// Whether descendants should be included recursively.
    pub recursive: bool,
    /// Whether regular files should be included.
    pub include_files: bool,
    /// Whether symlink entries should be included.
    pub include_symlinks: bool,
    /// Optional maximum number of entries to return.
    pub limit: Option<usize>,
}

impl ListOptions {
    /// Create default non-recursive listing options for `path`.
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            glob: None,
            recursive: false,
            include_files: true,
            include_symlinks: true,
            limit: None,
        }
    }
}
