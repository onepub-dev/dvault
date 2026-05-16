use crate::constants::{DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_TOTAL_BYTES};

/// Safety and behavior limits for extracting lockbox contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractPolicy {
    /// Maximum bytes allowed for any single extracted file.
    pub max_file_bytes: u64,
    /// Maximum total file bytes allowed across the extraction.
    pub max_total_bytes: u64,
    /// Maximum number of file records to extract.
    pub max_files: usize,
    /// Whether symlink records may be restored.
    pub restore_symlinks: bool,
    /// Whether stored permission bits should be applied to extracted files.
    pub restore_permissions: bool,
    /// Whether extraction may overwrite existing filesystem paths.
    pub overwrite: bool,
}

impl Default for ExtractPolicy {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_files: DEFAULT_MAX_FILES,
            restore_symlinks: false,
            restore_permissions: false,
            overwrite: false,
        }
    }
}
