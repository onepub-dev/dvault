use super::Lockbox;
use crate::lockbox_path::LockboxPath;
use crate::{Error, Result};

impl Lockbox {
    /// Delete a file or symlink from the lockbox.
    ///
    /// Returns `Error::InvalidPath` for directory-only paths, `Error::NotFound`
    /// if `path` does not name an existing entry, and storage errors if pending data
    /// must be flushed before deletion.
    pub fn delete(&mut self, path: &LockboxPath) -> Result<()> {
        let path = path.file_path()?;
        if self.should_discard_file_pages_after_flush()
            && self.pending_small_files.contains_key(path.as_str())
        {
            self.flush_bulk_small_file_packer()?;
        }
        self.remove_pending_small_file(&path);
        let old = self
            .toc_entries
            .get(path.as_str())
            .filter(|entry| !entry.deleted)
            .cloned()
            .ok_or_else(|| Error::NotFound(path.to_string()))?;
        self.pending_symlinks.remove(path.as_str());
        self.free_entry_slots(old.clone())?;
        let dirty_path = old.path.clone();
        self.toc_entries.remove(path.as_str());
        self.mark_toc_dirty(&dirty_path);
        Ok(())
    }

    /// Rename one file/symlink or a directory prefix.
    ///
    /// Returns `Error::InvalidPath` for unsafe file paths, self-nested
    /// directory moves, or generated destination paths that are not valid
    /// lockbox file paths. Returns `Error::NotFound` when the source file or
    /// directory prefix does not exist. Existing destination entries are
    /// replaced by the rename.
    pub fn rename(&mut self, from: &LockboxPath, to: &LockboxPath) -> Result<()> {
        if let Ok(from_path) = from.as_file_path() {
            if self
                .toc_entries
                .get(from_path)
                .filter(|entry| !entry.deleted)
                .is_some()
            {
                let from_path = from.file_path()?;
                let to_path = to.file_path()?;
                self.rename_toc_entry(&from_path, &to_path)?;
                return Ok(());
            }
        }

        let from_dir = from.as_str().to_string();
        let to_dir = to.as_str().to_string();
        if from_dir == to_dir {
            return Ok(());
        }
        if from_dir == "/" || to_dir.starts_with(&format!("{}/", from_dir.trim_end_matches('/'))) {
            return Err(Error::InvalidPath(to_dir));
        }

        let prefix = format!("{}/", from_dir.trim_end_matches('/'));
        let entries: Vec<_> = self
            .toc_entries
            .values()
            .filter(|entry| !entry.deleted && entry.path.starts_with(&prefix))
            .cloned()
            .collect();
        if entries.is_empty() {
            return Err(Error::NotFound(from_dir));
        }

        for entry in entries {
            let from_path = entry.path.clone();
            let suffix = &from_path[from_dir.trim_end_matches('/').len()..];
            let to_path = if to_dir == "/" {
                suffix.to_string()
            } else {
                format!("{}{}", to_dir.trim_end_matches('/'), suffix)
            };
            let to_path = LockboxPath::from_api(&to_path, false)?;
            self.rename_toc_entry(&from_path, &to_path)?;
        }
        Ok(())
    }

    fn rename_toc_entry(&mut self, from_path: &LockboxPath, to_path: &LockboxPath) -> Result<()> {
        if from_path == to_path {
            return Ok(());
        }

        if self.should_discard_file_pages_after_flush()
            && (self.pending_small_files.contains_key(from_path.as_str())
                || self.pending_small_files.contains_key(to_path.as_str()))
        {
            self.flush_bulk_small_file_packer()?;
        }

        if let Some(old_target) = self
            .toc_entries
            .get(to_path.as_str())
            .filter(|entry| !entry.deleted)
            .cloned()
        {
            self.pending_symlinks.remove(to_path.as_str());
            self.free_entry_slots(old_target)?;
            self.toc_entries.remove(to_path.as_str());
        }

        let mut entry = self
            .toc_entries
            .remove(from_path.as_str())
            .filter(|entry| !entry.deleted)
            .ok_or_else(|| Error::NotFound(from_path.to_string()))?;

        if let Some(pending) = self.remove_pending_small_file(from_path) {
            self.insert_pending_small_file(
                to_path.clone(),
                crate::file_chunk::PendingFileChunk {
                    path: to_path.clone(),
                    ..pending
                },
            );
        }
        if let Some(target) = self.pending_symlinks.remove(from_path.as_str()) {
            self.pending_symlinks.insert(to_path.clone(), target);
        } else if entry.node_kind == crate::node_kind::NodeKind::Symlink {
            let target = self.symlink_target_for_entry(&entry)?;
            self.free_entry_slots(entry.clone())?;
            self.pending_symlinks.insert(to_path.clone(), target);
        }

        entry.path = to_path.clone();
        self.toc_entries.insert(entry.path.clone(), entry);
        self.mark_toc_dirty(from_path);
        self.mark_toc_dirty(to_path);
        Ok(())
    }
}
