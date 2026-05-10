use crate::logical_path::LogicalPath;
use crate::Result;

#[derive(Debug, Clone)]
pub(crate) struct Symlink {
    path: LogicalPath,
    target: LogicalPath,
}

impl Symlink {
    pub(crate) fn from_api(path: &str, target: &str) -> Result<Self> {
        Ok(Self {
            path: LogicalPath::from_api(path, false)?,
            target: LogicalPath::from_api(target, false)?,
        })
    }

    pub(crate) fn path(&self) -> &LogicalPath {
        &self.path
    }

    pub(crate) fn target(&self) -> &LogicalPath {
        &self.target
    }
}
