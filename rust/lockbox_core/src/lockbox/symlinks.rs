use super::Lockbox;
use crate::constants::DEFAULT_SYMLINK_PERMISSIONS;
use crate::file_format::{decode_symlink_payload, encode_symlink_payload};
use crate::logical_path::{canonicalize_api_path as canonicalize_path, LogicalPath};
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::page::{
    encoded_object_len, uncompressed_objects_fit, PageObject, PageObjectKind,
    DEFAULT_METADATA_PAGE_BYTES,
};
use crate::symlink::Symlink;
use crate::{Error, Result};

impl Lockbox {
    pub fn put_symlink(&mut self, path: &str, target: &str) -> Result<()> {
        let symlink = Symlink::from_api(path, target)?;
        let path = symlink.path().as_str().to_string();
        let target = symlink.target().as_str().to_string();
        if self.should_discard_file_pages_after_flush()
            && self.pending_small_files.contains_key(&path)
        {
            self.flush_bulk_small_file_packer()?;
        }
        self.remove_pending_small_file(&path);

        if let Some(old) = self.manifest.get(path.as_str()) {
            self.free_entry_slots(old.clone())?;
        }

        self.pending_symlinks.insert(path.clone(), target.clone());
        let dirty_path = path.clone();
        let entry = ManifestEntry {
            path,
            len: 0,
            record_offset: 0,
            record_len: 0,
            record_object_id: 0,
            deleted: false,
            node_kind: NodeKind::Symlink,
            permissions: DEFAULT_SYMLINK_PERMISSIONS,
            chunks: Vec::new(),
        };
        self.manifest
            .insert(LogicalPath::from_canonical(entry.path.clone()), entry);
        self.mark_toc_dirty(&dirty_path);
        Ok(())
    }

    pub(crate) fn flush_pending_symlinks(&mut self) -> Result<()> {
        if self.pending_symlinks.is_empty() {
            return Ok(());
        }

        let pending = std::mem::take(&mut self.pending_symlinks);
        let mut pending_objects = Vec::new();
        let mut stream_len = 4usize;
        for (path, target) in pending {
            self.sequence += 1;
            let object = PageObject::new(
                PageObjectKind::Symlink,
                self.sequence,
                encode_symlink_payload(&path, &target),
            );
            let object_len = encoded_object_len(&object)?;
            if !pending_objects.is_empty()
                && !uncompressed_objects_fit(DEFAULT_METADATA_PAGE_BYTES, stream_len + object_len)
            {
                self.write_symlink_recovery_page(std::mem::take(&mut pending_objects))?;
                stream_len = 4;
            }
            if !uncompressed_objects_fit(DEFAULT_METADATA_PAGE_BYTES, 4 + object_len) {
                return Err(Error::SecurityLimitExceeded(
                    "symlink payload exceeds metadata page size".to_string(),
                ));
            }
            stream_len += object_len;
            pending_objects.push(PendingSymlinkObject { path, object });
        }
        if !pending_objects.is_empty() {
            self.write_symlink_recovery_page(pending_objects)?;
        }
        Ok(())
    }

    fn write_symlink_recovery_page(&mut self, pending: Vec<PendingSymlinkObject>) -> Result<()> {
        let page_offset = self.allocate_page_offset(DEFAULT_METADATA_PAGE_BYTES as u64)?;
        let objects = pending
            .iter()
            .map(|pending| pending.object.clone())
            .collect::<Vec<_>>();
        self.write_decoded_page_at(page_offset, self.sequence, objects)?;
        for pending in pending {
            if let Some(entry) = self.manifest.get_mut(pending.path.as_str()) {
                entry.record_offset = page_offset;
                entry.record_len = DEFAULT_METADATA_PAGE_BYTES as u64;
                entry.record_object_id = pending.object.id;
                self.dirty_toc_paths
                    .insert(LogicalPath::from_canonical(entry.path.clone()));
            }
        }
        Ok(())
    }

    pub fn get_symlink_target(&self, path: &str) -> Result<String> {
        let path = canonicalize_path(path, false)?;
        let entry = self
            .manifest
            .get(path.as_str())
            .filter(|entry| !entry.deleted && entry.node_kind == NodeKind::Symlink)
            .ok_or_else(|| Error::NotFound(path.clone()))?;
        self.symlink_target_for_entry(entry)
    }

    pub(crate) fn symlink_target_for_entry(&self, entry: &ManifestEntry) -> Result<String> {
        if let Some(target) = self.pending_symlinks.get(entry.path.as_str()) {
            return Ok(target.clone());
        }
        if entry.record_offset == 0 || entry.record_object_id == 0 {
            return Err(Error::CorruptRecord);
        }
        self.with_page_object(entry.record_offset, entry.record_object_id, |object| {
            if object.kind != PageObjectKind::Symlink {
                return Err(Error::CorruptRecord);
            }
            let (path, target) = object.with_payload(decode_symlink_payload)??;
            if path != entry.path {
                return Err(Error::CorruptRecord);
            }
            Ok(target)
        })
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

struct PendingSymlinkObject {
    path: String,
    object: PageObject,
}
