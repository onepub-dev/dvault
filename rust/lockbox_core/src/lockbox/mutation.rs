use super::Lockbox;
use crate::logical_path::canonicalize_api_path as canonicalize_path;
use crate::logical_path::LogicalPath;
use crate::{Error, Result};

impl Lockbox {
    pub fn delete(&mut self, path: &str) -> Result<()> {
        let path = canonicalize_path(path, false)?;
        if self.should_discard_file_pages_after_flush()
            && self.pending_small_files.contains_key(&path)
        {
            self.flush_bulk_small_file_packer()?;
        }
        self.remove_pending_small_file(&path);
        let old = self
            .manifest
            .get(path.as_str())
            .filter(|entry| !entry.deleted)
            .cloned()
            .ok_or_else(|| Error::NotFound(path.clone()))?;
        self.pending_symlinks.remove(&path);
        self.free_entry_slots(old.clone())?;
        let dirty_path = old.path.clone();
        self.manifest.remove(path.as_str());
        self.mark_toc_dirty(&dirty_path);
        Ok(())
    }

    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        if let Ok(from_path) = canonicalize_path(from, false) {
            if self
                .manifest
                .get(from_path.as_str())
                .filter(|entry| !entry.deleted)
                .is_some()
            {
                let to_path = canonicalize_path(to, false)?;
                self.rename_manifest_entry(&from_path, &to_path)?;
                return Ok(());
            }
        }

        let from_dir = canonicalize_path(from, true)?;
        let to_dir = canonicalize_path(to, true)?;
        if from_dir == to_dir {
            return Ok(());
        }
        if from_dir == "/" || to_dir.starts_with(&format!("{}/", from_dir.trim_end_matches('/'))) {
            return Err(Error::InvalidPath(to_dir));
        }

        let prefix = format!("{}/", from_dir.trim_end_matches('/'));
        let entries: Vec<_> = self
            .manifest
            .values()
            .filter(|entry| !entry.deleted && entry.path.starts_with(&prefix))
            .cloned()
            .collect();
        if entries.is_empty() {
            return Err(Error::NotFound(from_dir));
        }

        for entry in entries {
            let suffix = &entry.path[from_dir.trim_end_matches('/').len()..];
            let to_path = if to_dir == "/" {
                suffix.to_string()
            } else {
                format!("{}{}", to_dir.trim_end_matches('/'), suffix)
            };
            self.rename_manifest_entry(&entry.path, &to_path)?;
        }
        Ok(())
    }

    fn rename_manifest_entry(&mut self, from_path: &str, to_path: &str) -> Result<()> {
        if from_path == to_path {
            return Ok(());
        }

        if self.should_discard_file_pages_after_flush()
            && (self.pending_small_files.contains_key(from_path)
                || self.pending_small_files.contains_key(to_path))
        {
            self.flush_bulk_small_file_packer()?;
        }

        if let Some(old_target) = self
            .manifest
            .get(to_path)
            .filter(|entry| !entry.deleted)
            .cloned()
        {
            self.pending_symlinks.remove(to_path);
            self.free_entry_slots(old_target)?;
            self.manifest.remove(to_path);
        }

        let mut entry = self
            .manifest
            .remove(from_path)
            .filter(|entry| !entry.deleted)
            .ok_or_else(|| Error::NotFound(from_path.to_string()))?;

        if let Some(pending) = self.remove_pending_small_file(from_path) {
            self.insert_pending_small_file(
                to_path.to_string(),
                crate::file_chunk::PendingFileChunk {
                    path: to_path.to_string(),
                    ..pending
                },
            );
        }
        if let Some(target) = self.pending_symlinks.remove(from_path) {
            self.pending_symlinks.insert(to_path.to_string(), target);
        } else if entry.node_kind == crate::node_kind::NodeKind::Symlink {
            let target = self.symlink_target_for_entry(&entry)?;
            self.free_entry_slots(entry.clone())?;
            self.pending_symlinks.insert(to_path.to_string(), target);
        }

        entry.path = to_path.to_string();
        self.manifest
            .insert(LogicalPath::from_canonical(entry.path.clone()), entry);
        self.mark_toc_dirty(from_path);
        self.mark_toc_dirty(to_path);
        Ok(())
    }
}
