#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListOptions {
    pub path: String,
    pub glob: Option<String>,
    pub recursive: bool,
    pub include_files: bool,
    pub include_symlinks: bool,
    pub limit: Option<usize>,
}

impl ListOptions {
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
