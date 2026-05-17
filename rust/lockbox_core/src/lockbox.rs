use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use crate::commit_root::decode_commit_root;
use crate::constants::HEADER_LEN;
use crate::env_btree::{EnvLeaf, EnvTreeNode, EnvValue};
use crate::fast_hash::FastBuildHasher;
use crate::file_chunk::{PackedSmallFile, PendingFileChunk};
use crate::file_format::{
    decode_toc_node, read_header, write_header, TocInternal, TocLeaf, TocNode, TocTreeNode,
};
use crate::free_index::{decode_free_index_internal, decode_free_index_leaf};
use crate::free_slot::{FreeSlot, FreeSpace};
use crate::key_directory::{
    best_key_directory, decode_key_directory_decoded_page, scan_key_directories,
    DecodedKeyDirectory,
};
use crate::key_slot::KeySlot;
use crate::lockbox_id::LockboxId;
use crate::lockbox_path::LockboxPath;
use crate::page::{
    page_size_for_objects, DecodedPage, PageObject, PageObjectKind, DEFAULT_METADATA_PAGE_BYTES,
    DEFAULT_PAGE_BYTES, PAGE_MAGIC,
};
use crate::page_cache::{PageCache, PageReadKey, PageSecurity, PageWritePolicy};
use crate::page_object_packer::PageObjectPacker;
use crate::record::{DecodedRecord, RecordHeader, RecordKind};
use crate::secret_vec::SecretVec;
use crate::storage::{Storage, StorageBackend};
use crate::toc_entry::TocEntry;
use crate::{CacheStats, EnvName, Error, LockboxOptions, RecoveryReport, Result, WorkloadProfile};
use zeroize::Zeroize;

mod commit;
mod env;
mod extraction;
mod files;
mod key_management;
mod listing;
mod mutation;
mod recovery;
mod symlinks;

pub use env::EnvValueRef;
#[cfg(feature = "vault-bridge")]
pub use key_management::UnlockedContentKey;
pub use key_management::{LockboxCreate, LockboxUnlock};
pub use recovery::RecoveryScanner;

/// Read-only diagnostics for an opened lockbox.
///
/// The inspector intentionally exposes no mutation methods. It is a separate
/// handle so page/cache details do not sit on the main high-level `Lockbox`
/// API.
pub struct LockboxInspector<'a> {
    lockbox: &'a Lockbox,
}

/// Open encrypted lockbox container.
///
/// A `Lockbox` owns the encrypted storage backend plus the decrypted metadata
/// needed to make changes. Mutations are staged in memory until `commit()` is
/// called; reopening a lockbox after an interrupted commit returns the last
/// published state.
#[derive(Debug)]
pub struct Lockbox {
    storage: StorageBackend,
    key: SecretVec,
    sequence: u64,
    commit_root_offset: u64,
    toc_root_offset: u64,
    env_root_offset: u64,
    free_index_offset: u64,
    key_directory_offset: u64,
    key_directory_mirror_offsets: [u64; 2],
    key_directory_generation: u64,
    dirty_key_directory: bool,
    lockbox_id: LockboxId,
    key_slots: Vec<KeySlot>,
    toc_entries: BTreeMap<LockboxPath, TocEntry>,
    toc_root: Option<TocTreeNode>,
    toc_leaves: Vec<TocLeaf>,
    dirty_toc_paths: BTreeSet<LockboxPath>,
    env_vars: RefCell<Option<BTreeMap<EnvName, EnvValue>>>,
    env_root: Option<EnvTreeNode>,
    env_leaves: Vec<EnvLeaf>,
    dirty_env: bool,
    page_manager: RefCell<PageCache>,
    workload_profile: WorkloadProfile,
    free_space: FreeSpace,
    record_ref_counts: std::collections::HashMap<u64, usize, FastBuildHasher>,
    pending_redactions: BTreeMap<u64, PendingRedaction>,
    redacted_free_slots: Vec<FreeSlot>,
    pending_small_files: BTreeMap<LockboxPath, PendingFileChunk>,
    pending_small_file_bytes: usize,
    bulk_small_file_packer: PageObjectPacker<PackedSmallFile>,
    pending_symlinks: BTreeMap<LockboxPath, LockboxPath>,
    needs_packing: bool,
}

impl Lockbox {
    pub(crate) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            storage: self.storage.clone(),
            key: self.key.try_clone()?,
            sequence: self.sequence,
            commit_root_offset: self.commit_root_offset,
            toc_root_offset: self.toc_root_offset,
            env_root_offset: self.env_root_offset,
            free_index_offset: self.free_index_offset,
            key_directory_offset: self.key_directory_offset,
            key_directory_mirror_offsets: self.key_directory_mirror_offsets,
            key_directory_generation: self.key_directory_generation,
            dirty_key_directory: self.dirty_key_directory,
            lockbox_id: self.lockbox_id,
            key_slots: self.key_slots.clone(),
            toc_entries: self.toc_entries.clone(),
            toc_root: self.toc_root.clone(),
            toc_leaves: self.toc_leaves.clone(),
            dirty_toc_paths: self.dirty_toc_paths.clone(),
            env_vars: RefCell::new(self.env_vars.borrow().clone()),
            env_root: self.env_root.clone(),
            env_leaves: self.env_leaves.clone(),
            dirty_env: self.dirty_env,
            page_manager: RefCell::new(self.page_manager.borrow().clone()),
            workload_profile: self.workload_profile,
            free_space: self.free_space.clone(),
            record_ref_counts: self.record_ref_counts.clone(),
            pending_redactions: self.pending_redactions.clone(),
            redacted_free_slots: self.redacted_free_slots.clone(),
            pending_small_files: self.pending_small_files.clone(),
            pending_small_file_bytes: self.pending_small_file_bytes,
            bulk_small_file_packer: self.bulk_small_file_packer.clone(),
            pending_symlinks: self.pending_symlinks.clone(),
            needs_packing: self.needs_packing,
        })
    }

    #[cfg(test)]
    pub fn create(key: impl AsRef<[u8]>) -> Self {
        Self::create_with_options(key, LockboxOptions::default())
    }

    #[cfg(test)]
    pub fn create_with_options(key: impl AsRef<[u8]>, options: LockboxOptions) -> Self {
        Self::create_with_lockbox_id_and_options(
            key,
            LockboxId::new_random().expect("system random source failed"),
            options,
        )
    }

    #[cfg(test)]
    pub fn create_with_lockbox_id(key: impl AsRef<[u8]>, lockbox_id: LockboxId) -> Self {
        Self::create_with_lockbox_id_and_options(key, lockbox_id, LockboxOptions::default())
    }

    #[cfg(test)]
    pub fn create_with_lockbox_id_and_options(
        key: impl AsRef<[u8]>,
        lockbox_id: LockboxId,
        options: LockboxOptions,
    ) -> Self {
        let key = SecretVec::try_from_slice(key.as_ref())
            .expect("secure allocation failed while creating lockbox");
        Self::create_with_secret_key_and_options(key, lockbox_id, options)
    }

    pub(crate) fn create_with_secret_key_and_options(
        key: SecretVec,
        lockbox_id: LockboxId,
        options: LockboxOptions,
    ) -> Self {
        let mut bytes = vec![0; HEADER_LEN];
        write_header(&mut bytes, 0, 0, 0, lockbox_id);
        Self {
            storage: StorageBackend::memory(bytes),
            key,
            sequence: 0,
            commit_root_offset: 0,
            toc_root_offset: 0,
            env_root_offset: 0,
            free_index_offset: 0,
            key_directory_offset: 0,
            key_directory_mirror_offsets: [0, 0],
            key_directory_generation: 0,
            dirty_key_directory: false,
            lockbox_id,
            key_slots: Vec::new(),
            toc_entries: BTreeMap::new(),
            toc_root: None,
            toc_leaves: Vec::new(),
            dirty_toc_paths: BTreeSet::new(),
            env_vars: RefCell::new(Some(BTreeMap::new())),
            env_root: None,
            env_leaves: Vec::new(),
            dirty_env: false,
            page_manager: RefCell::new(PageCache::new(options.cache_limit)),
            workload_profile: options.workload_profile,
            free_space: FreeSpace::default(),
            record_ref_counts: std::collections::HashMap::with_hasher(FastBuildHasher::default()),
            pending_redactions: BTreeMap::new(),
            redacted_free_slots: Vec::new(),
            pending_small_files: BTreeMap::new(),
            pending_small_file_bytes: 0,
            bulk_small_file_packer: PageObjectPacker::new(DEFAULT_PAGE_BYTES),
            pending_symlinks: BTreeMap::new(),
            needs_packing: false,
        }
    }

    #[cfg(test)]
    pub fn open(bytes: Vec<u8>, key: impl AsRef<[u8]>) -> Result<Self> {
        Self::open_with_options(bytes, key, LockboxOptions::default())
    }

    #[cfg(test)]
    pub fn open_with_options(
        bytes: Vec<u8>,
        key: impl AsRef<[u8]>,
        options: LockboxOptions,
    ) -> Result<Self> {
        Self::open_storage(StorageBackend::memory(bytes), key, options)
    }

    #[cfg(test)]
    pub(crate) fn open_storage(
        storage: StorageBackend,
        key: impl AsRef<[u8]>,
        options: LockboxOptions,
    ) -> Result<Self> {
        let key = SecretVec::try_from_slice(key.as_ref())?;
        Self::open_storage_with_secret_key(storage, key, options)
    }

    pub(crate) fn open_storage_with_secret_key(
        storage: StorageBackend,
        key: SecretVec,
        options: LockboxOptions,
    ) -> Result<Self> {
        let header = storage.read_at(0, HEADER_LEN)?;
        let header_result = read_header(&header);
        let scanned_key_directory = if header_result.is_err() {
            let all_bytes = storage.read_all()?;
            best_key_directory(scan_key_directories(&all_bytes, None))
        } else {
            None
        };
        let (header_root_offset, sequence, header_key_directory_offset, lockbox_id) =
            match header_result {
                Ok(header) => header,
                Err(_) => {
                    let Some(key_directory) = scanned_key_directory.as_ref() else {
                        return Err(Error::CorruptHeader);
                    };
                    (0, 0, key_directory.offset, key_directory.lockbox_id)
                }
            };
        let mut lockbox = Self {
            storage,
            key,
            sequence,
            commit_root_offset: 0,
            toc_root_offset: 0,
            env_root_offset: 0,
            free_index_offset: 0,
            key_directory_offset: header_key_directory_offset,
            key_directory_mirror_offsets: [0, 0],
            key_directory_generation: 0,
            dirty_key_directory: false,
            lockbox_id,
            key_slots: Vec::new(),
            toc_entries: BTreeMap::new(),
            toc_root: None,
            toc_leaves: Vec::new(),
            dirty_toc_paths: BTreeSet::new(),
            env_vars: RefCell::new(None),
            env_root: None,
            env_leaves: Vec::new(),
            dirty_env: false,
            page_manager: RefCell::new(PageCache::new(options.cache_limit)),
            workload_profile: options.workload_profile,
            free_space: FreeSpace::default(),
            record_ref_counts: std::collections::HashMap::with_hasher(FastBuildHasher::default()),
            pending_redactions: BTreeMap::new(),
            redacted_free_slots: Vec::new(),
            pending_small_files: BTreeMap::new(),
            pending_small_file_bytes: 0,
            bulk_small_file_packer: PageObjectPacker::new(DEFAULT_PAGE_BYTES),
            pending_symlinks: BTreeMap::new(),
            needs_packing: false,
        };

        let mut toc_root_offset = header_root_offset;
        if header_root_offset > 0 {
            let commit_root = match lockbox.read_commit_root_at(header_root_offset) {
                Ok(commit_root) => {
                    lockbox.commit_root_offset = header_root_offset;
                    commit_root
                }
                Err(_) => {
                    let Some((offset, commit_root)) = lockbox.find_latest_valid_commit_root()?
                    else {
                        return Err(Error::CorruptHeader);
                    };
                    lockbox.commit_root_offset = offset;
                    commit_root
                }
            };
            lockbox.sequence = commit_root.sequence;
            lockbox.key_directory_offset = commit_root.key_directory_offset;
            lockbox.key_directory_mirror_offsets = commit_root.key_directory_mirror_offsets;
            lockbox.key_directory_generation = commit_root.key_directory_generation;
            lockbox.free_index_offset = commit_root.free_index_root_offset;
            lockbox.env_root_offset = commit_root.env_root_offset;
            toc_root_offset = commit_root.toc_root_offset;
        } else if let Some((offset, commit_root)) = lockbox.find_latest_valid_commit_root()? {
            lockbox.commit_root_offset = offset;
            lockbox.sequence = commit_root.sequence;
            lockbox.key_directory_offset = commit_root.key_directory_offset;
            lockbox.key_directory_mirror_offsets = commit_root.key_directory_mirror_offsets;
            lockbox.key_directory_generation = commit_root.key_directory_generation;
            lockbox.free_index_offset = commit_root.free_index_root_offset;
            lockbox.env_root_offset = commit_root.env_root_offset;
            toc_root_offset = commit_root.toc_root_offset;
        }
        if let Some(directory) = lockbox
            .read_best_key_directory(scanned_key_directory.as_ref())
            .unwrap_or(None)
        {
            lockbox.key_directory_generation = directory.generation;
            lockbox.key_slots = directory.slots;
        }

        if toc_root_offset > 0 {
            let (toc_entries, root, leaves) = lockbox.decode_toc_btree(toc_root_offset)?;
            lockbox.toc_root_offset = toc_root_offset;
            lockbox.toc_entries = toc_entries;
            lockbox.toc_root = Some(root);
            lockbox.toc_leaves = leaves;
            lockbox.rebuild_record_ref_counts();
            if lockbox.free_index_offset > 0 {
                let slots = lockbox.read_free_index_slots(lockbox.free_index_offset, 0)?;
                lockbox.free_space.replace_slots(slots);
            } else {
                lockbox.rebuild_free_slots_from_toc();
            }
            Ok(lockbox)
        } else {
            Ok(lockbox)
        }
    }

    /// Return the stable id embedded in this lockbox.
    pub fn lockbox_id(&self) -> LockboxId {
        self.lockbox_id
    }

    /// Set cache behavior tuned for the caller's expected access pattern.
    pub fn set_workload_profile(&mut self, profile: WorkloadProfile) {
        self.workload_profile = profile;
    }

    /// Return the currently selected workload profile.
    pub fn workload_profile(&self) -> WorkloadProfile {
        self.workload_profile
    }

    pub(crate) fn should_discard_file_pages_after_flush(&self) -> bool {
        matches!(self.workload_profile, WorkloadProfile::BulkImport)
    }

    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        self.storage.read_all()
    }

    fn read_best_key_directory(
        &self,
        scanned_fallback: Option<&DecodedKeyDirectory>,
    ) -> Result<Option<DecodedKeyDirectory>> {
        let mut directories = Vec::new();
        for offset in [
            self.key_directory_offset,
            self.key_directory_mirror_offsets[0],
            self.key_directory_mirror_offsets[1],
        ] {
            if offset == 0 {
                continue;
            }
            if let Ok(page) = self.read_page(offset) {
                let Ok(directory) =
                    decode_key_directory_decoded_page(&page, offset, Some(self.lockbox_id))
                else {
                    continue;
                };
                directories.push(directory);
            }
        }
        if let Some(directory) = scanned_fallback {
            if directory.lockbox_id == self.lockbox_id {
                directories.push(directory.clone());
            }
        }
        Ok(best_key_directory(directories))
    }

    pub(crate) fn read_record(&self, offset: u64) -> Result<DecodedRecord> {
        let decoded = self.read_page(offset)?;
        let Some(object) = decoded.objects.first() else {
            return Err(Error::CorruptRecord);
        };
        let kind = record_kind_from_object_kind(object.kind)?;
        Ok(DecodedRecord {
            header: RecordHeader {
                kind,
                sequence: decoded.sequence,
                total_len: page_size_for_objects(&decoded.objects) as u64,
            },
            offset,
            object_id: object.id,
            payload: object.with_payload(|payload| payload.to_vec())?,
        })
    }

    pub(crate) fn read_page(&self, offset: u64) -> Result<crate::page::DecodedPage> {
        self.with_page(offset, |page| Ok(page.clone()))
    }

    pub(crate) fn with_page<R>(
        &self,
        offset: u64,
        f: impl FnOnce(&crate::page::DecodedPage) -> Result<R>,
    ) -> Result<R> {
        let page = self.key.with_bytes(|key| {
            self.page_manager.borrow_mut().read_page(
                &self.storage,
                offset,
                self.lockbox_id,
                PageSecurity::Normal,
                PageReadKey::Normal(key),
            )
        })??;
        f(&page)
    }

    pub(crate) fn with_secure_page<R>(
        &self,
        offset: u64,
        f: impl FnOnce(&crate::page::DecodedPage) -> Result<R>,
    ) -> Result<R> {
        let mut content_key = self
            .key
            .with_bytes(crate::crypto::derive_page_content_key)?;
        let page = self.page_manager.borrow_mut().read_page(
            &self.storage,
            offset,
            self.lockbox_id,
            PageSecurity::Secure,
            PageReadKey::Secure(&content_key),
        );
        content_key.zeroize();
        f(&page?)
    }

    pub(crate) fn with_page_object<R>(
        &self,
        offset: u64,
        object_id: u64,
        f: impl FnOnce(&PageObject) -> Result<R>,
    ) -> Result<R> {
        self.with_page(offset, |page| {
            let object = page
                .objects
                .iter()
                .find(|object| object.id == object_id)
                .ok_or(Error::CorruptRecord)?;
            f(object)
        })
    }

    pub(crate) fn allocate_page_offset(&mut self, page_size: u64) -> Result<u64> {
        if let Some(slot) = self.free_space.allocate(page_size) {
            Ok(slot.offset)
        } else {
            self.next_append_page_offset()
        }
    }

    pub(crate) fn next_append_page_offset(&self) -> Result<u64> {
        Ok(self.page_manager.borrow().virtual_len(self.storage.len()?))
    }

    pub(crate) fn write_decoded_page_at(
        &mut self,
        offset: u64,
        sequence: u64,
        objects: Vec<PageObject>,
    ) -> Result<()> {
        self.write_decoded_page_at_with_policy(
            offset,
            sequence,
            objects,
            PageWritePolicy::RetainAfterFlush,
        )
    }

    pub(crate) fn write_decoded_page_at_with_policy(
        &mut self,
        offset: u64,
        sequence: u64,
        objects: Vec<PageObject>,
        policy: PageWritePolicy,
    ) -> Result<()> {
        let page_size = page_size_for_objects(&objects);
        self.page_manager
            .borrow_mut()
            .stage_decoded_page_with_policy(
                offset,
                page_size,
                DecodedPage {
                    page_id: offset,
                    sequence,
                    objects,
                },
                policy,
            )
    }

    pub(crate) fn write_insert_only_page_at(
        &mut self,
        offset: u64,
        sequence: u64,
        objects: Vec<PageObject>,
    ) -> Result<()> {
        self.write_decoded_page_at_with_policy(
            offset,
            sequence,
            objects,
            PageWritePolicy::DiscardAfterFlush,
        )
    }

    pub(crate) fn flush_dirty_pages(&mut self) -> Result<()> {
        self.key.with_bytes(|key| {
            self.page_manager.borrow_mut().flush_dirty_pages(
                &mut self.storage,
                self.lockbox_id,
                key,
            )
        })?
    }

    pub(crate) fn flush_discardable_pages(&mut self) -> Result<()> {
        self.key.with_bytes(|key| {
            self.page_manager.borrow_mut().flush_discardable_pages(
                &mut self.storage,
                self.lockbox_id,
                key,
            )
        })?
    }

    pub(crate) fn has_dirty_pages(&self) -> bool {
        self.page_manager.borrow().has_dirty_pages()
    }

    /// Return a read-only diagnostics view for this lockbox.
    pub fn inspector(&self) -> LockboxInspector<'_> {
        LockboxInspector { lockbox: self }
    }

    pub(crate) fn mark_toc_dirty(&mut self, path: &LockboxPath) {
        self.dirty_toc_paths.insert(path.clone());
    }

    pub(crate) fn mark_toc_dirty_paths<'a>(
        &mut self,
        paths: impl IntoIterator<Item = &'a LockboxPath>,
    ) {
        for path in paths {
            self.mark_toc_dirty(path);
        }
    }

    pub(crate) fn free_entry_slots(&mut self, entry: TocEntry) -> Result<()> {
        for record in self.entry_record_refs(&entry)? {
            self.schedule_page_object_redaction(record.offset, record.len, record.object_id);
        }
        Ok(())
    }

    pub(crate) fn schedule_page_object_redaction(&mut self, offset: u64, len: u64, object_id: u64) {
        let redaction = self
            .pending_redactions
            .entry(offset)
            .or_insert_with(|| PendingRedaction {
                len,
                object_ids: BTreeSet::new(),
            });
        redaction.len = len;
        redaction.object_ids.insert(object_id);
    }

    pub(crate) fn apply_pending_redactions(&mut self) -> Result<()> {
        let pending = std::mem::take(&mut self.pending_redactions);
        for (offset, redaction) in pending {
            let count = self
                .record_ref_counts
                .get(&offset)
                .copied()
                .or_else(|| self.read_page(offset).ok().map(|page| page.objects.len()))
                .unwrap_or(0);
            if count == 0 {
                continue;
            }
            let remaining = count.saturating_sub(redaction.object_ids.len());
            if remaining == 0 {
                self.record_ref_counts.remove(&offset);
                self.zero_page_and_free(FreeSlot {
                    offset,
                    len: redaction.len,
                })?;
            } else {
                self.relocate_page_without_objects(
                    offset,
                    redaction.len,
                    &redaction.object_ids,
                    remaining,
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn add_entry_record_refs(&mut self, entry: &TocEntry) {
        if entry.deleted {
            return;
        }
        for (offset, _) in entry_record_slots(entry) {
            *self.record_ref_counts.entry(offset).or_insert(0) += 1;
        }
    }

    fn rebuild_record_ref_counts(&mut self) {
        self.record_ref_counts.clear();
        let entries = self
            .toc_entries
            .values()
            .filter(|entry| !entry.deleted)
            .cloned()
            .collect::<Vec<_>>();
        for entry in &entries {
            self.add_entry_record_refs(entry);
        }
    }

    fn rebuild_free_slots_from_toc(&mut self) {
        self.free_space.clear();
        let deleted_slots: Vec<_> = self
            .toc_entries
            .values()
            .filter(|entry| entry.deleted)
            .map(|entry| FreeSlot {
                offset: entry.record_offset,
                len: entry.record_len,
            })
            .collect();
        for slot in deleted_slots {
            self.add_free_slot(slot);
        }
    }

    fn add_free_slot(&mut self, slot: FreeSlot) {
        self.free_space.add(slot);
    }

    pub(crate) fn zero_page_and_free(&mut self, slot: FreeSlot) -> Result<()> {
        let _len = usize::try_from(slot.len).map_err(|_| {
            Error::SecurityLimitExceeded("page length exceeds addressable memory".to_string())
        })?;
        if slot.offset.saturating_add(slot.len) <= self.storage.len()? {
            self.page_manager
                .borrow_mut()
                .stage_zeroed_page(slot.offset, slot.len);
            self.redacted_free_slots.push(slot);
        }
        Ok(())
    }

    pub(crate) fn publish_redacted_free_slots(&mut self) {
        let slots = std::mem::take(&mut self.redacted_free_slots);
        for slot in slots {
            self.add_free_slot(slot);
        }
    }

    fn relocate_page_without_objects(
        &mut self,
        old_offset: u64,
        old_len: u64,
        removed_object_ids: &BTreeSet<u64>,
        remaining_refs: usize,
    ) -> Result<()> {
        let decoded = self.read_page(old_offset)?;
        let kept_object_ids = decoded
            .objects
            .iter()
            .filter(|object| !removed_object_ids.contains(&object.id))
            .map(|object| object.id)
            .collect::<BTreeSet<_>>();
        let kept_objects = decoded
            .objects
            .into_iter()
            .filter(|object| kept_object_ids.contains(&object.id))
            .collect::<Vec<_>>();
        if kept_objects.is_empty() {
            self.record_ref_counts.remove(&old_offset);
            self.zero_page_and_free(FreeSlot {
                offset: old_offset,
                len: old_len,
            })?;
            return Ok(());
        }

        self.sequence += 1;
        let new_offset = self.allocate_page_offset(page_size_for_objects(&kept_objects) as u64)?;
        self.write_decoded_page_at(new_offset, self.sequence, kept_objects)?;
        self.repoint_live_entries(old_offset, new_offset, &kept_object_ids);
        self.record_ref_counts.remove(&old_offset);
        self.record_ref_counts.insert(new_offset, remaining_refs);
        self.zero_page_and_free(FreeSlot {
            offset: old_offset,
            len: old_len,
        })?;
        Ok(())
    }

    fn repoint_live_entries(
        &mut self,
        old_offset: u64,
        new_offset: u64,
        kept_object_ids: &BTreeSet<u64>,
    ) {
        let mut dirty = Vec::new();
        for entry in self.toc_entries.values_mut() {
            if entry.deleted {
                continue;
            }
            let mut changed = false;
            if entry.chunks.is_empty() {
                if entry.record_offset == old_offset {
                    entry.record_offset = new_offset;
                    changed = true;
                }
            } else {
                for chunk in &mut entry.chunks {
                    for fragment in &mut chunk.fragments {
                        if fragment.page_offset == old_offset
                            && kept_object_ids.contains(&fragment.object_id)
                        {
                            fragment.page_offset = new_offset;
                            changed = true;
                        }
                    }
                }
            }
            if changed {
                dirty.push(entry.path.clone());
            }
        }
        self.mark_toc_dirty_paths(dirty.iter());
    }

    fn entry_record_refs(&self, entry: &TocEntry) -> Result<Vec<RecordRef>> {
        if entry.record_len == 0 && entry.chunks.is_empty() {
            return Ok(Vec::new());
        }
        if entry.chunks.is_empty() {
            if entry.record_object_id != 0 {
                return Ok(vec![RecordRef {
                    offset: entry.record_offset,
                    len: entry.record_len,
                    object_id: entry.record_object_id,
                }]);
            }
            let record = self.read_record(entry.record_offset)?;
            return Ok(vec![RecordRef {
                offset: entry.record_offset,
                len: entry.record_len,
                object_id: record.object_id,
            }]);
        }
        Ok(entry
            .chunks
            .iter()
            .flat_map(|chunk| {
                chunk.fragments.iter().map(|fragment| RecordRef {
                    offset: fragment.page_offset,
                    len: fragment.page_len,
                    object_id: fragment.object_id,
                })
            })
            .collect())
    }

    fn decode_toc_btree(
        &self,
        root_offset: u64,
    ) -> Result<(BTreeMap<LockboxPath, TocEntry>, TocTreeNode, Vec<TocLeaf>)> {
        let mut toc_entries = BTreeMap::new();
        let root = self.decode_toc_node_into(root_offset, &mut toc_entries, 0)?;
        let mut leaves = Vec::new();
        root.collect_leaves(&mut leaves);
        leaves.sort_by(|left, right| {
            let left_path = left
                .entries
                .first()
                .map(|entry| entry.path.as_str())
                .unwrap_or("");
            let right_path = right
                .entries
                .first()
                .map(|entry| entry.path.as_str())
                .unwrap_or("");
            left_path.cmp(right_path)
        });
        Ok((toc_entries, root, leaves))
    }

    fn decode_toc_node_into(
        &self,
        offset: u64,
        toc_entries: &mut BTreeMap<LockboxPath, TocEntry>,
        depth: usize,
    ) -> Result<TocTreeNode> {
        if depth > 8 {
            return Err(Error::CorruptRecord);
        }
        match decode_toc_node(&self.read_toc_node_payload(offset)?)? {
            TocNode::Leaf(entries) => {
                let leaf_entries = entries.clone();
                for entry in entries {
                    toc_entries.insert(entry.path.clone(), entry);
                }
                Ok(TocTreeNode::Leaf(TocLeaf {
                    offset,
                    entries: leaf_entries,
                }))
            }
            TocNode::Internal(children) => {
                let mut nodes = Vec::with_capacity(children.len());
                for child in children {
                    nodes.push(self.decode_toc_node_into(child.offset, toc_entries, depth + 1)?);
                }
                Ok(TocTreeNode::Internal(TocInternal {
                    offset,
                    children: nodes,
                }))
            }
        }
    }

    fn read_toc_node_payload(&self, offset: u64) -> Result<Vec<u8>> {
        let decoded = self.read_page(offset)?;
        let Some(toc_object) = decoded.objects.iter().find(|object| {
            matches!(
                object.kind,
                PageObjectKind::TocLeaf | PageObjectKind::TocInternal
            )
        }) else {
            return Err(Error::CorruptRecord);
        };
        toc_object.with_payload(|payload| payload.to_vec())
    }

    fn read_commit_root_at(&self, offset: u64) -> Result<crate::commit_root::CommitRoot> {
        let decoded = self.read_page(offset)?;
        let Some(commit_root_object) = decoded
            .objects
            .iter()
            .find(|object| object.kind == PageObjectKind::CommitRoot)
        else {
            return Err(Error::CorruptHeader);
        };
        commit_root_object.with_payload(decode_commit_root)?
    }

    fn find_latest_valid_commit_root(
        &self,
    ) -> Result<Option<(u64, crate::commit_root::CommitRoot)>> {
        let mut best = None;
        let mut offset = HEADER_LEN as u64;
        let len = self.storage.len()?;
        while offset + crate::page::PAGE_HEADER_LEN as u64 <= len {
            let magic = self.storage.read_at(offset, 8)?;
            if magic.as_slice() == PAGE_MAGIC {
                if offset + DEFAULT_METADATA_PAGE_BYTES as u64 > len {
                    break;
                }
                if let Ok(commit_root) = self.read_commit_root_at(offset) {
                    if best.as_ref().is_none_or(
                        |(_, existing): &(u64, crate::commit_root::CommitRoot)| {
                            commit_root.sequence > existing.sequence
                        },
                    ) {
                        best = Some((offset, commit_root));
                    }
                    offset += DEFAULT_METADATA_PAGE_BYTES as u64;
                    continue;
                }
            }
            offset += 1;
        }
        Ok(best)
    }

    fn read_free_index_slots(&self, offset: u64, depth: usize) -> Result<Vec<FreeSlot>> {
        if depth > 8 {
            return Err(Error::CorruptRecord);
        }
        let decoded = self.read_page(offset)?;
        if let Some(leaf) = decoded
            .objects
            .iter()
            .find(|object| object.kind == PageObjectKind::FreeIndexLeaf)
        {
            return leaf.with_payload(decode_free_index_leaf)?;
        }
        let Some(internal) = decoded
            .objects
            .iter()
            .find(|object| object.kind == PageObjectKind::FreeIndexInternal)
        else {
            return Err(Error::CorruptHeader);
        };
        let mut slots = Vec::new();
        let children = internal.with_payload(decode_free_index_internal)??;
        for child in children {
            slots.extend(self.read_free_index_slots(child.offset, depth + 1)?);
        }
        Ok(slots)
    }
}

impl LockboxInspector<'_> {
    /// Return the current persisted storage length in bytes.
    ///
    /// Returns `Error::Io` if the backing storage cannot report its length.
    pub fn storage_len(&self) -> Result<u64> {
        self.lockbox.storage.len()
    }

    /// Return decoded-page cache usage and hit/miss counters.
    pub fn cache_stats(&self) -> CacheStats {
        self.lockbox.page_manager.borrow().stats()
    }

    /// Return page-level metadata useful for diagnostics and visualization.
    ///
    /// Returns storage or authentication errors if lockbox bytes cannot be
    /// materialized for inspection.
    pub fn inspect_pages(&self) -> Result<Vec<crate::PageInspection>> {
        let bytes = self.lockbox.bytes()?;
        self.lockbox.key.with_bytes(|key| {
            Ok(crate::page::inspect_pages(
                &bytes,
                self.lockbox.lockbox_id,
                key,
            ))
        })?
    }

    /// Scan the current persisted storage and return a recovery report.
    pub fn recovery_report(&self) -> RecoveryReport {
        match self.lockbox.bytes() {
            Ok(bytes) => self
                .lockbox
                .key
                .with_bytes(|key| RecoveryScanner::scan_bytes(bytes, key))
                .unwrap_or_else(|_| corrupt_recovery_report()),
            Err(_err) => corrupt_recovery_report(),
        }
    }
}

fn corrupt_recovery_report() -> RecoveryReport {
    RecoveryReport {
        intact_files: Vec::new(),
        intact_file_count: 0,
        partial_files: 0,
        corrupt_records: 1,
        toc_recovered: false,
    }
}

fn record_kind_from_object_kind(kind: PageObjectKind) -> Result<RecordKind> {
    match kind {
        PageObjectKind::PackedFileData | PageObjectKind::FileData => Ok(RecordKind::FilePage),
        PageObjectKind::Symlink => Ok(RecordKind::Symlink),
        PageObjectKind::EnvSet => Ok(RecordKind::Env),
        PageObjectKind::EnvDelete => Ok(RecordKind::EnvDelete),
        PageObjectKind::Delete => Ok(RecordKind::Delete),
        PageObjectKind::TocLeaf | PageObjectKind::TocInternal => Ok(RecordKind::TocNode),
        PageObjectKind::CommitRoot => Ok(RecordKind::CommitRoot),
        PageObjectKind::FreeIndexLeaf | PageObjectKind::FreeIndexInternal => {
            Ok(RecordKind::FreeIndex)
        }
        PageObjectKind::KeyDirectory | PageObjectKind::EnvLeaf | PageObjectKind::EnvInternal => {
            Err(Error::CorruptRecord)
        }
    }
}

fn entry_record_slots(entry: &TocEntry) -> Vec<(u64, u64)> {
    if entry.record_len == 0 && entry.chunks.is_empty() {
        return Vec::new();
    }
    if entry.chunks.is_empty() {
        return vec![(entry.record_offset, entry.record_len)];
    }
    entry
        .chunks
        .iter()
        .flat_map(|chunk| {
            chunk
                .fragments
                .iter()
                .map(|fragment| (fragment.page_offset, fragment.page_len))
        })
        .collect()
}

#[derive(Debug, Clone, Copy)]
struct RecordRef {
    offset: u64,
    len: u64,
    object_id: u64,
}

#[derive(Debug, Clone)]
struct PendingRedaction {
    len: u64,
    object_ids: BTreeSet<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(path: impl AsRef<str>) -> crate::LockboxPath {
        crate::LockboxPath::new(path).unwrap()
    }

    #[test]
    fn path_is_not_visible_in_cleartext() {
        let mut lb = Lockbox::create("secret");
        lb.add_file(&p("/private/tax.pdf"), b"1234", false).unwrap();
        lb.commit().unwrap();

        let bytes = lb.to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("/private/tax.pdf"));
    }

    #[test]
    fn free_slots_are_coalesced() {
        let mut lb = Lockbox::create("secret");
        lb.add_free_slot(FreeSlot {
            offset: 200,
            len: 100,
        });
        lb.add_free_slot(FreeSlot {
            offset: 100,
            len: 100,
        });
        lb.add_free_slot(FreeSlot {
            offset: 400,
            len: 80,
        });

        let slots = lb.free_space.slots_by_offset();
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].offset, 100);
        assert_eq!(slots[0].len, 200);
        assert_eq!(slots[1].offset, 400);
        assert_eq!(slots[1].len, 80);
    }
}
