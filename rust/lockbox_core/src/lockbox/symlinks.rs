use super::Lockbox;
use crate::constants::DEFAULT_SYMLINK_PERMISSIONS;
use crate::format::{decode_symlink_payload, encode_symlink_payload};
use crate::logical_path::{canonicalize_api_path as canonicalize_path, LogicalPath};
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::record::RecordKind;
use crate::symlink::Symlink;
use crate::{Error, Result};

impl Lockbox {
    pub fn put_symlink(&mut self, path: &str, target: &str) -> Result<()> {
        let symlink = Symlink::from_api(path, target)?;
        let path = symlink.path().as_str().to_string();
        let target = symlink.target().as_str().to_string();
        self.pending_small_files.remove(&path);
        self.sequence += 1;
        let payload = encode_symlink_payload(&path, &target);
        let offset = self.write_object_page(RecordKind::Symlink, self.sequence, payload)?;
        let record_len = crate::page::DEFAULT_PAGE_BYTES as u64;

        if let Some(old) = self.manifest.get(path.as_str()) {
            self.free_entry_slots(old.clone())?;
        }

        let dirty_path = path.clone();
        let entry = ManifestEntry {
            path,
            len: 0,
            record_offset: offset,
            record_len,
            deleted: false,
            node_kind: NodeKind::Symlink,
            permissions: DEFAULT_SYMLINK_PERMISSIONS,
            symlink_target: Some(target),
            chunks: Vec::new(),
        };
        self.add_entry_record_refs(&entry);
        self.manifest
            .insert(LogicalPath::from_canonical(entry.path.clone()), entry);
        self.mark_toc_dirty(&dirty_path);
        Ok(())
    }

    pub fn get_symlink_target(&self, path: &str) -> Result<String> {
        let path = canonicalize_path(path, false)?;
        let entry = self
            .manifest
            .get(path.as_str())
            .filter(|entry| !entry.deleted && entry.node_kind == NodeKind::Symlink)
            .ok_or_else(|| Error::NotFound(path.clone()))?;
        let record = self.read_record(entry.record_offset)?;
        let (_, target) = decode_symlink_payload(&record.payload)?;
        Ok(target)
    }

    pub fn is_symlink(&self, path: &str) -> bool {
        let Ok(path) = canonicalize_path(path, false) else {
            return false;
        };
        self.manifest
            .get(path.as_str())
            .filter(|entry| !entry.deleted)
            .map(|entry| entry.node_kind == NodeKind::Symlink)
            .unwrap_or(false)
    }
}
