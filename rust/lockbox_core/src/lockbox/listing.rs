use super::Lockbox;
use crate::lockbox_path::{glob_matches, validate_glob};
use crate::node_kind::NodeKind;
use crate::{ListIter, ListOptions, LockboxEntry, LockboxPath, Result};

impl Lockbox {
    /// Return an iterator over entries matching listing options.
    ///
    /// Returns `Error::InvalidPath` if the list root or glob pattern is unsafe.
    /// Iteration can also return `Error::CorruptRecord` if a symlink entry
    /// points at invalid stored metadata.
    pub fn list_iter(&self, options: ListOptions) -> Result<ListIter<'_>> {
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
            Some(self.public_entry_for_toc(entry))
        });
        Ok(ListIter::new(Box::new(iter)))
    }

    /// List direct child entries below a logical path.
    ///
    /// Returns the same errors as `list_iter`.
    pub fn list(&self, path: &LockboxPath) -> Result<Vec<LockboxEntry>> {
        self.list_iter(ListOptions::new(path))?.collect()
    }

    /// List entries below a path filtered by a glob pattern.
    ///
    /// Returns the same errors as `list_iter`, including `Error::InvalidPath`
    /// for unsafe glob patterns.
    pub fn list_glob(&self, path: &LockboxPath, glob: &str) -> Result<Vec<LockboxEntry>> {
        let mut options = ListOptions::new(path);
        options.glob = Some(glob.to_string());
        options.recursive = glob.contains("**") || glob.contains('/');
        self.list_iter(options)?.collect()
    }

    /// Return metadata for one file or symlink.
    pub fn stat(&self, path: &LockboxPath) -> Option<LockboxEntry> {
        let path = path.as_file_path().ok()?;
        self.toc_entries
            .get(path)
            .filter(|e| !e.deleted)
            .and_then(|entry| self.public_entry_for_toc(entry).ok())
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

    fn public_entry_for_toc(&self, entry: &crate::toc_entry::TocEntry) -> Result<LockboxEntry> {
        let mut public = entry.to_public_entry();
        if entry.node_kind == NodeKind::Symlink {
            public.symlink_target = Some(self.symlink_target_for_entry(entry)?);
        }
        Ok(public)
    }
}
