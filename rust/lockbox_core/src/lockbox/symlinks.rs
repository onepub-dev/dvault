use super::Lockbox;
use crate::constants::DEFAULT_SYMLINK_PERMISSIONS;
use crate::format::{decode_symlink_payload, encode_record, encode_symlink_payload, read_record};
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::record::RecordKind;
use crate::security::{canonicalize_path, validate_symlink};
use crate::{Error, Result};

impl Lockbox {
    pub fn put_symlink(&mut self, path: &str, target: &str) -> Result<()> {
        let path = canonicalize_path(path, false)?;
        let target = canonicalize_path(target, false)?;
        validate_symlink(&path, &target)?;
        self.sequence += 1;
        let payload = encode_symlink_payload(&path, &target);
        let record = encode_record(
            RecordKind::Symlink,
            self.sequence,
            &payload,
            self.key.expose(),
        );
        let record_len = record.len() as u64;
        let offset = self.write_record(record);

        if let Some(old) = self.manifest.get(&path) {
            self.free_entry_slots(old.clone());
        }

        self.manifest.insert(
            path.clone(),
            ManifestEntry {
                path,
                len: 0,
                record_offset: offset,
                record_len,
                deleted: false,
                node_kind: NodeKind::Symlink,
                permissions: DEFAULT_SYMLINK_PERMISSIONS,
                symlink_target: Some(target),
                chunks: Vec::new(),
            },
        );
        Ok(())
    }

    pub fn get_symlink_target(&self, path: &str) -> Result<String> {
        let path = canonicalize_path(path, false)?;
        let entry = self
            .manifest
            .get(&path)
            .filter(|entry| !entry.deleted && entry.node_kind == NodeKind::Symlink)
            .ok_or_else(|| Error::NotFound(path.clone()))?;
        let record = read_record(&self.bytes, entry.record_offset, self.key.expose())?;
        let (_, target) = decode_symlink_payload(&record.payload)?;
        Ok(target)
    }

    pub fn is_symlink(&self, path: &str) -> bool {
        let Ok(path) = canonicalize_path(path, false) else {
            return false;
        };
        self.manifest
            .get(&path)
            .filter(|entry| !entry.deleted)
            .map(|entry| entry.node_kind == NodeKind::Symlink)
            .unwrap_or(false)
    }
}
