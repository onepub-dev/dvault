use crate::constants::{DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_TOTAL_BYTES};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractPolicy {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_files: usize,
    pub restore_symlinks: bool,
    pub restore_permissions: bool,
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
