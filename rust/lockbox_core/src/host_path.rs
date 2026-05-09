use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct HostPath(PathBuf);

impl HostPath {
    pub(crate) fn new(path: impl AsRef<Path>) -> Self {
        Self(path.as_ref().to_path_buf())
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }
}
