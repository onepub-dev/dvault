use super::Lockbox;
use crate::lockbox_path::{glob_matches, validate_glob};
use crate::node_kind::NodeKind;
use crate::{ListOptions, LockboxEntry, LockboxPath, Result};

impl Lockbox {
    /// Return an iterator over entries matching listing options.
    ///
    /// Returns `Error::InvalidPath` if the list root or glob pattern is unsafe.
    /// Iteration returns only table-of-contents metadata. It does not read
    /// symlink page objects; call `get_symlink_target` for symlink targets.
    pub fn list(
        &self,
        options: ListOptions,
    ) -> Result<impl Iterator<Item = Result<LockboxEntry>> + '_> {
        let path = options.path.as_str().to_string();
        let glob = match &options.glob {
            Some(pattern) => Some(validate_glob(pattern)?),
            None => None,
        };
        let prefix = if path == "/" {
            "/".to_string()
        } else {
            format!("{}/", path.trim_end_matches('/'))
        };
        let mut yielded = 0usize;
        let iter = self.toc_entries.values().filter_map(move |entry| {
            if entry.deleted || !entry.path.starts_with(&prefix) {
                return None;
            }
            if entry.node_kind == NodeKind::File && !options.include_files {
                return None;
            }
            if entry.node_kind == NodeKind::Symlink && !options.include_symlinks {
                return None;
            }
            let rest = &entry.path[prefix.len()..];
            if rest.is_empty() {
                return None;
            }
            if !options.recursive && rest.contains('/') {
                return None;
            }
            if let Some(pattern) = &glob {
                if !glob_matches(pattern, rest) && !glob_matches(pattern, &entry.path) {
                    return None;
                }
            }
            if let Some(limit) = options.limit {
                if yielded >= limit {
                    return None;
                }
            }
            yielded += 1;
            Some(Ok(entry.to_public_entry()))
        });
        Ok(iter)
    }

    /// Return metadata for one file or symlink.
    pub fn stat(&self, path: &LockboxPath) -> Option<LockboxEntry> {
        let path = path.as_file_path().ok()?;
        self.toc_entries
            .get(path)
            .filter(|e| !e.deleted)
            .map(|entry| entry.to_public_entry())
    }

    /// Return true when `path` names an existing file or symlink entry.
    ///
    /// Directory-only paths such as `/` and `/docs/` return `false` because
    /// directories are inferred from entry prefixes rather than stored as
    /// entries. Invalid file paths also return `false`.
    pub fn exists(&self, path: &LockboxPath) -> bool {
        let Ok(path) = path.as_file_path() else {
            return false;
        };
        self.toc_entries
            .get(path)
            .filter(|entry| !entry.deleted)
            .is_some()
    }
}
