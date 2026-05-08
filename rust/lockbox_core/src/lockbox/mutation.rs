use super::Lockbox;
use crate::format::{encode_delete_payload, encode_record};
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::record::RecordKind;
use crate::security::canonicalize_path;
use crate::{Error, Result};

impl Lockbox {
    pub fn delete(&mut self, path: &str) -> Result<()> {
        let path = canonicalize_path(path, false)?;
        let old = self
            .manifest
            .get(&path)
            .filter(|entry| !entry.deleted)
            .cloned()
            .ok_or_else(|| Error::NotFound(path.clone()))?;
        self.sequence += 1;
        let payload = encode_delete_payload(&path);
        let record = encode_record(
            RecordKind::Delete,
            self.sequence,
            &payload,
            self.key.expose(),
        );
        self.write_record(record);
        self.free_entry_slots(old.clone());
        self.manifest.insert(
            path,
            ManifestEntry {
                deleted: true,
                chunks: Vec::new(),
                ..old
            },
        );
        Ok(())
    }

    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        if let Ok(from_path) = canonicalize_path(from, false) {
            if let Some(entry) = self
                .manifest
                .get(&from_path)
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
