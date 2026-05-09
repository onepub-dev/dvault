use super::Lockbox;
use crate::constants::DEFAULT_MAX_SEGMENT_BODY_BYTES;
use crate::format::encode_delete_payloads;
use crate::logical_path::canonicalize_api_path as canonicalize_path;
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::record::RecordKind;
use crate::{Error, Result};

impl Lockbox {
    pub fn delete(&mut self, path: &str) -> Result<()> {
        let path = canonicalize_path(path, false)?;
        self.pending_small_files.remove(&path);
        let old = self
            .manifest
            .get(path.as_str())
            .filter(|entry| !entry.deleted)
            .cloned()
            .ok_or_else(|| Error::NotFound(path.clone()))?;
        if old.record_len != 0 || !old.chunks.is_empty() {
            self.pending_deletes.push(path.clone());
        }
        self.free_entry_slots(old.clone());
        let dirty_path = old.path.clone();
        self.manifest.remove(path.as_str());
        self.mark_toc_dirty(&dirty_path);
        Ok(())
    }

    pub(crate) fn flush_pending_deletes(&mut self) -> Result<()> {
        if self.pending_deletes.is_empty() {
            return Ok(());
        }

        let pending = std::mem::take(&mut self.pending_deletes);
        let mut batch = Vec::new();
        let mut batch_size = 0usize;
        for path in pending {
            let entry_size = 2 + path.len();
            if !batch.is_empty() && batch_size + entry_size > DEFAULT_MAX_SEGMENT_BODY_BYTES {
                self.write_delete_batch(&batch)?;
                batch.clear();
                batch_size = 0;
            }
            batch_size += entry_size;
            batch.push(path);
        }
        if !batch.is_empty() {
            self.write_delete_batch(&batch)?;
        }
        Ok(())
    }

    fn write_delete_batch(&mut self, paths: &[String]) -> Result<()> {
        self.sequence += 1;
        let refs = paths.iter().map(String::as_str).collect::<Vec<_>>();
        let payload = encode_delete_payloads(&refs);
        self.write_object_page(RecordKind::Delete, self.sequence, payload)?;
        Ok(())
    }

    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        if let Ok(from_path) = canonicalize_path(from, false) {
            if let Some(entry) = self
                .manifest
                .get(from_path.as_str())
                .filter(|entry| !entry.deleted)
                .cloned()
            {
                self.rename_entry(&from_path, to, &entry)?;
                self.delete(from)?;
                return Ok(());
            }
        }

        let from_dir = canonicalize_path(from, true)?;
        let to_dir = canonicalize_path(to, true)?;
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
            self.rename_entry(&entry.path, &to_path, &entry)?;
            self.delete(&entry.path)?;
        }
        Ok(())
    }

    fn rename_entry(&mut self, from_path: &str, to: &str, entry: &ManifestEntry) -> Result<()> {
        match entry.node_kind {
            NodeKind::File => {
                let data = self.get_file(from_path)?;
                self.put_file_with_permissions(to, &data, entry.permissions)
            }
            NodeKind::Symlink => {
                let target = self.get_symlink_target(from_path)?;
                self.put_symlink(to, &target)
            }
        }
    }
}
