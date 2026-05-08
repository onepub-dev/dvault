use super::Lockbox;
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::security::{canonicalize_path, glob_matches, validate_glob};
use crate::{Entry, ListIter, ListOptions, Result};

impl Lockbox {
    pub fn list_iter(&self, options: ListOptions) -> Result<ListIter<'_>> {
        let path = canonicalize_path(&options.path, true)?;
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
        let iter = self.manifest.values().filter_map(move |entry| {
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
        Ok(ListIter::new(Box::new(iter)))
    }

    pub fn list(&self, path: &str) -> Result<Vec<Entry>> {
        self.list_iter(ListOptions::new(path))?.collect()
    }

    pub fn list_glob(&self, path: &str, glob: &str) -> Result<Vec<Entry>> {
        let mut options = ListOptions::new(path);
        options.glob = Some(glob.to_string());
        options.recursive = glob.contains("**") || glob.contains('/');
        self.list_iter(options)?.collect()
    }

    pub fn stat(&self, path: &str) -> Option<Entry> {
        let path = canonicalize_path(path, false).ok()?;
        self.manifest
            .get(&path)
            .filter(|e| !e.deleted)
            .map(ManifestEntry::to_public_entry)
    }
}
