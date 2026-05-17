use super::Lockbox;
use crate::constants::DEFAULT_SYMLINK_PERMISSIONS;
use crate::file_format::{decode_symlink_payload, encode_symlink_payload};
use crate::lockbox_path::LockboxPath;
use crate::node_kind::NodeKind;
use crate::page::{
    encoded_object_len, uncompressed_objects_fit, PageObject, PageObjectKind,
    DEFAULT_METADATA_PAGE_BYTES,
};
use crate::toc_entry::TocEntry;
use crate::{Error, Result};

impl Lockbox {
    /// Add or replace a symbolic link.
    ///
    /// When `replace` is `false`, returns `Error::AlreadyExists` if `path`
    /// already names an existing file or symlink. When `replace` is `true`,
    /// returns `Error::NotFound` if there is no existing entry to replace. Returns
    /// `Error::InvalidPath` for directory-only or unsafe lockbox paths and
    /// propagates storage errors from the write.
    pub fn add_symlink(
        &mut self,
        path: &LockboxPath,
        target: &LockboxPath,
        replace: bool,
    ) -> Result<()> {
        let path = path.file_path()?;
        let target = target.file_path()?;
        self.validate_replace_intent(&path, replace)?;
        if self.should_discard_file_pages_after_flush()
            && self.pending_small_files.contains_key(path.as_str())
        {
            self.flush_bulk_small_file_packer()?;
        }
        self.remove_pending_small_file(&path);

        if let Some(old) = self.toc_entries.get(path.as_str()) {
            self.free_entry_slots(old.clone())?;
        }

        self.pending_symlinks.insert(path.clone(), target.clone());
        let entry = TocEntry {
            path: path.clone(),
            len: 0,
            record_offset: 0,
            record_len: 0,
            record_object_id: 0,
            deleted: false,
            node_kind: NodeKind::Symlink,
            permissions: DEFAULT_SYMLINK_PERMISSIONS,
            chunks: Vec::new(),
        };
        self.toc_entries.insert(path.clone(), entry);
        self.mark_toc_dirty(&path);
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
            if let Some(entry) = self.toc_entries.get_mut(pending.path.as_str()) {
                entry.record_offset = page_offset;
                entry.record_len = DEFAULT_METADATA_PAGE_BYTES as u64;
                entry.record_object_id = pending.object.id;
                self.dirty_toc_paths.insert(entry.path.clone());
            }
        }
        Ok(())
    }

    /// Return the target path for a symbolic link.
    ///
    /// Returns `Error::InvalidPath` for directory-only paths,
    /// `Error::NotFound` if `path` is absent or not a symlink, and
    /// `Error::CorruptRecord` if the stored symlink metadata is inconsistent.
    pub fn get_symlink_target(&self, path: &LockboxPath) -> Result<LockboxPath> {
        let path = path.as_file_path()?;
        let entry = self
            .toc_entries
            .get(path)
            .filter(|entry| !entry.deleted && entry.node_kind == NodeKind::Symlink)
            .ok_or_else(|| Error::NotFound(path.to_string()))?;
        self.symlink_target_for_entry(entry)
    }

    pub(crate) fn symlink_target_for_entry(&self, entry: &TocEntry) -> Result<LockboxPath> {
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

    /// Return true when the logical path is a symbolic link.
    pub fn is_symlink(&self, path: &LockboxPath) -> bool {
        let Ok(path) = path.as_file_path() else {
            return false;
        };
        self.toc_entries
            .get(path)
            .filter(|entry| !entry.deleted)
            .map(|entry| entry.node_kind == NodeKind::Symlink)
            .unwrap_or(false)
    }
}

struct PendingSymlinkObject {
    path: LockboxPath,
    object: PageObject,
}
