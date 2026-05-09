use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use crate::commit_root::decode_commit_root;
use crate::constants::HEADER_LEN;
use crate::fast_hash::FastBuildHasher;
use crate::file_chunk::PendingFileChunk;
use crate::format::{
    decode_toc_node, read_header, write_header, TocInternal, TocLeaf, TocNode, TocTreeNode,
};
use crate::free_index::{decode_free_index_internal, decode_free_index_leaf};
use crate::free_slot::{FreeSlot, FreeSpace};
use crate::key_directory::read_key_directory_from_storage;
use crate::key_slot::KeySlot;
use crate::logical_path::LogicalPath;
use crate::manifest_entry::ManifestEntry;
use crate::record::{DecodedRecord, RecordHeader, RecordKind};
use crate::secret_bytes::SecretBytes;
use crate::segment_cache::SegmentManager;
use crate::segment_page::{
    DecodedSegmentPage, SegmentObject, SegmentObjectKind, DEFAULT_SEGMENT_PAGE_BYTES,
    SEGMENT_PAGE_MAGIC,
};
use crate::storage::{Storage, StorageBackend};
use crate::vault_id::VaultId;
use crate::{CacheLimit, CacheStats, Error, LockboxOptions, Result};

mod commit;
mod env;
mod extraction;
mod files;
mod key_management;
mod listing;
mod mutation;
mod recovery;
mod symlinks;

pub use key_management::UnlockedVaultKey;

#[derive(Debug, Clone)]
pub struct Lockbox {
    storage: StorageBackend,
    key: SecretBytes,
    sequence: u64,
    commit_root_offset: u64,
    manifest_offset: u64,
    free_index_offset: u64,
    key_directory_offset: u64,
    vault_id: VaultId,
    key_slots: Vec<KeySlot>,
    manifest: BTreeMap<LogicalPath, ManifestEntry>,
    toc_root: Option<TocTreeNode>,
    toc_leaves: Vec<TocLeaf>,
    dirty_toc_paths: BTreeSet<LogicalPath>,
    env_vars: RefCell<Option<BTreeMap<String, String>>>,
    segment_manager: RefCell<SegmentManager>,
    free_space: FreeSpace,
    record_ref_counts: std::collections::HashMap<u64, usize, FastBuildHasher>,
    pending_small_files: BTreeMap<String, PendingFileChunk>,
    pending_deletes: Vec<String>,
    needs_packing: bool,
}

impl Lockbox {
    pub fn create(key: impl AsRef<[u8]>) -> Self {
        Self::create_with_options(key, LockboxOptions::default())
    }

    pub fn create_with_options(key: impl AsRef<[u8]>, options: LockboxOptions) -> Self {
        Self::create_with_vault_id_and_options(
            key,
            VaultId::new_random().expect("system random source failed"),
            options,
        )
    }

    pub fn create_with_vault_id(key: impl AsRef<[u8]>, vault_id: VaultId) -> Self {
        Self::create_with_vault_id_and_options(key, vault_id, LockboxOptions::default())
    }

    pub fn create_with_vault_id_and_options(
        key: impl AsRef<[u8]>,
        vault_id: VaultId,
        options: LockboxOptions,
    ) -> Self {
        let key = SecretBytes::new(key.as_ref().to_vec());
        let mut bytes = vec![0; HEADER_LEN];
        write_header(&mut bytes, 0, 0, 0, vault_id);
        Self {
            storage: StorageBackend::memory(bytes),
            key,
            sequence: 0,
            commit_root_offset: 0,
            manifest_offset: 0,
            free_index_offset: 0,
            key_directory_offset: 0,
            vault_id,
            key_slots: Vec::new(),
            manifest: BTreeMap::new(),
            toc_root: None,
            toc_leaves: Vec::new(),
            dirty_toc_paths: BTreeSet::new(),
            env_vars: RefCell::new(Some(BTreeMap::new())),
            segment_manager: RefCell::new(SegmentManager::new(options.cache_limit)),
            free_space: FreeSpace::default(),
            record_ref_counts: std::collections::HashMap::with_hasher(FastBuildHasher::default()),
            pending_small_files: BTreeMap::new(),
            pending_deletes: Vec::new(),
            needs_packing: false,
        }
    }

    pub fn open(bytes: Vec<u8>, key: impl AsRef<[u8]>) -> Result<Self> {
        Self::open_with_options(bytes, key, LockboxOptions::default())
    }

    pub fn open_with_options(
        bytes: Vec<u8>,
        key: impl AsRef<[u8]>,
        options: LockboxOptions,
    ) -> Result<Self> {
        Self::open_storage(StorageBackend::memory(bytes), key, options)
    }

    pub(crate) fn open_storage(
        storage: StorageBackend,
        key: impl AsRef<[u8]>,
        options: LockboxOptions,
    ) -> Result<Self> {
        let key = SecretBytes::new(key.as_ref().to_vec());
        let header = storage.read_at(0, HEADER_LEN)?;
        let (header_root_offset, sequence, header_key_directory_offset, vault_id) =
            read_header(&header)?;
        let mut lockbox = Self {
            storage,
            key,
            sequence,
            commit_root_offset: 0,
            manifest_offset: 0,
            free_index_offset: 0,
            key_directory_offset: header_key_directory_offset,
            vault_id,
            key_slots: Vec::new(),
            manifest: BTreeMap::new(),
            toc_root: None,
            toc_leaves: Vec::new(),
            dirty_toc_paths: BTreeSet::new(),
            env_vars: RefCell::new(None),
            segment_manager: RefCell::new(SegmentManager::new(options.cache_limit)),
            free_space: FreeSpace::default(),
            record_ref_counts: std::collections::HashMap::with_hasher(FastBuildHasher::default()),
            pending_small_files: BTreeMap::new(),
            pending_deletes: Vec::new(),
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
            lockbox.free_index_offset = commit_root.free_index_root_offset;
            toc_root_offset = commit_root.toc_root_offset;
        }
        lockbox.key_slots =
            read_key_directory_from_storage(&lockbox.storage, lockbox.key_directory_offset)?;

        if toc_root_offset > 0 {
            let (manifest, root, leaves) = lockbox.decode_toc_btree(toc_root_offset)?;
            lockbox.manifest_offset = toc_root_offset;
            lockbox.manifest = manifest;
            lockbox.toc_root = Some(root);
            lockbox.toc_leaves = leaves;
            lockbox.rebuild_record_ref_counts();
            if lockbox.free_index_offset > 0 {
                let slots = lockbox.read_free_index_slots(lockbox.free_index_offset, 0)?;
                lockbox.free_space.replace_slots(slots);
            } else {
                lockbox.rebuild_free_slots_from_manifest();
            }
            Ok(lockbox)
        } else {
            Ok(lockbox)
        }
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn read_vault_id(bytes: &[u8]) -> Result<VaultId> {
        crate::header::read_vault_id(bytes)
    }

    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        self.storage.read_all()
    }

    pub(crate) fn read_record(&self, offset: u64) -> Result<DecodedRecord> {
        let magic = self.storage.read_at(offset, 8)?;
        if magic.as_slice() != SEGMENT_PAGE_MAGIC {
            return Err(Error::CorruptRecord);
        }
        let decoded = self.read_segment_page(offset)?;
        let Some(object) = decoded.objects.first() else {
            return Err(Error::CorruptRecord);
        };
        let kind = record_kind_from_object_kind(object.kind)?;
        Ok(DecodedRecord {
            header: RecordHeader {
                kind,
                sequence: decoded.sequence,
                total_len: DEFAULT_SEGMENT_PAGE_BYTES as u64,
            },
            offset,
            payload: object.payload.clone(),
        })
    }

    pub(crate) fn write_object_page(
        &mut self,
        kind: RecordKind,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<u64> {
        let page_offset = self.allocate_segment_page_offset()?;
        let object = SegmentObject {
            kind: object_kind_from_record_kind(kind)?,
            id: sequence,
            payload,
        };
        let page = crate::segment_page::encode_segment_page(
            DEFAULT_SEGMENT_PAGE_BYTES,
            self.vault_id,
            page_offset,
            sequence,
            self.key.expose(),
            std::slice::from_ref(&object),
        )?;
        self.write_segment_page_at(page_offset, &page)?;
        self.cache_decoded_segment_page(page_offset, sequence, vec![object]);
        Ok(page_offset)
    }

    pub(crate) fn read_segment_page(
        &self,
        offset: u64,
    ) -> Result<crate::segment_page::DecodedSegmentPage> {
        self.segment_manager.borrow_mut().read_segment_page(
            &self.storage,
            offset,
            DEFAULT_SEGMENT_PAGE_BYTES,
            self.vault_id,
            self.key.expose(),
        )
    }

    pub(crate) fn allocate_segment_page_offset(&mut self) -> Result<u64> {
        if let Some(slot) = self.free_space.allocate(DEFAULT_SEGMENT_PAGE_BYTES as u64) {
            Ok(slot.offset)
        } else {
            self.storage.len()
        }
    }

    pub(crate) fn write_segment_page_at(&mut self, offset: u64, page: &[u8]) -> Result<()> {
        if page.len() != DEFAULT_SEGMENT_PAGE_BYTES {
            return Err(Error::CorruptRecord);
        }
        if offset == self.storage.len()? {
            let appended = self
                .segment_manager
                .borrow_mut()
                .append_segment_page(&mut self.storage, page)?;
            if appended != offset {
                return Err(Error::CorruptRecord);
            }
        } else {
            self.segment_manager.borrow_mut().write_segment_page(
                &mut self.storage,
                offset,
                page,
            )?;
        }
        Ok(())
    }

    pub(crate) fn cache_decoded_segment_page(
        &mut self,
        offset: u64,
        sequence: u64,
        objects: Vec<SegmentObject>,
    ) {
        self.segment_manager.borrow_mut().insert_page(
            offset,
            DecodedSegmentPage {
                page_id: offset,
                sequence,
                objects,
            },
            DEFAULT_SEGMENT_PAGE_BYTES as u64,
        );
    }

    pub fn set_cache_limit(&self, limit: CacheLimit) {
        self.segment_manager.borrow_mut().set_limit(limit);
    }

    pub fn trim_cache(&self) {
        self.segment_manager.borrow_mut().clear();
    }

    pub fn trim_cache_to(&self, bytes: u64) {
        self.segment_manager.borrow_mut().trim_to(bytes);
    }

    pub fn cache_stats(&self) -> CacheStats {
        self.segment_manager.borrow().stats()
    }

    pub(crate) fn mark_toc_dirty(&mut self, path: &str) {
        self.dirty_toc_paths
            .insert(LogicalPath::from_canonical(path.to_string()));
    }

    pub(crate) fn mark_toc_dirty_paths<'a>(&mut self, paths: impl IntoIterator<Item = &'a str>) {
        for path in paths {
            self.mark_toc_dirty(path);
        }
    }

    pub(crate) fn free_entry_slots(&mut self, entry: ManifestEntry) {
        for (offset, len) in entry_record_slots(&entry) {
            let Some(count) = self.record_ref_counts.get_mut(&offset) else {
                continue;
            };
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.record_ref_counts.remove(&offset);
                self.add_free_slot(FreeSlot { offset, len });
            }
        }
    }

    pub(crate) fn add_entry_record_refs(&mut self, entry: &ManifestEntry) {
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
            .manifest
            .values()
            .filter(|entry| !entry.deleted)
            .cloned()
            .collect::<Vec<_>>();
        for entry in &entries {
            self.add_entry_record_refs(entry);
        }
    }

    fn rebuild_free_slots_from_manifest(&mut self) {
        self.free_space.clear();
        let deleted_slots: Vec<_> = self
            .manifest
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

    fn decode_toc_btree(
        &self,
        root_offset: u64,
    ) -> Result<(
        BTreeMap<LogicalPath, ManifestEntry>,
        TocTreeNode,
        Vec<TocLeaf>,
    )> {
        let mut manifest = BTreeMap::new();
        let root = self.decode_toc_node_into(root_offset, &mut manifest, 0)?;
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
        Ok((manifest, root, leaves))
    }

    fn decode_toc_node_into(
        &self,
        offset: u64,
        manifest: &mut BTreeMap<LogicalPath, ManifestEntry>,
        depth: usize,
    ) -> Result<TocTreeNode> {
        if depth > 8 {
            return Err(Error::CorruptRecord);
        }
        match decode_toc_node(&self.read_toc_node_payload(offset)?)? {
            TocNode::Leaf(entries) => {
                let leaf_entries = entries.clone();
                for entry in entries {
                    manifest.insert(LogicalPath::from_canonical(entry.path.clone()), entry);
                }
                Ok(TocTreeNode::Leaf(TocLeaf {
                    offset,
                    entries: leaf_entries,
                }))
            }
            TocNode::Internal(children) => {
                let mut nodes = Vec::with_capacity(children.len());
                for child in children {
                    nodes.push(self.decode_toc_node_into(child.offset, manifest, depth + 1)?);
                }
                Ok(TocTreeNode::Internal(TocInternal {
                    offset,
                    children: nodes,
                }))
            }
        }
    }

    fn read_toc_node_payload(&self, offset: u64) -> Result<Vec<u8>> {
        let magic = self.storage.read_at(offset, 8)?;
        if magic.as_slice() != SEGMENT_PAGE_MAGIC {
            return Err(Error::CorruptRecord);
        }
        let decoded = self.read_segment_page(offset)?;
        let Some(toc_object) = decoded.objects.iter().find(|object| {
            matches!(
                object.kind,
                SegmentObjectKind::TocLeaf | SegmentObjectKind::TocInternal
            )
        }) else {
            return Err(Error::CorruptRecord);
        };
        Ok(toc_object.payload.clone())
    }

    fn read_commit_root_at(&self, offset: u64) -> Result<crate::commit_root::CommitRoot> {
        let magic = self.storage.read_at(offset, 8)?;
        if magic.as_slice() != SEGMENT_PAGE_MAGIC {
            return Err(Error::CorruptHeader);
        }
        let decoded = self.read_segment_page(offset)?;
        let Some(commit_root_object) = decoded
            .objects
            .iter()
            .find(|object| object.kind == SegmentObjectKind::CommitRoot)
        else {
            return Err(Error::CorruptHeader);
        };
        decode_commit_root(&commit_root_object.payload)
    }

    fn find_latest_valid_commit_root(
        &self,
    ) -> Result<Option<(u64, crate::commit_root::CommitRoot)>> {
        let mut best = None;
        let mut offset = HEADER_LEN as u64;
        let len = self.storage.len()?;
        while offset + crate::segment_page::SEGMENT_PAGE_HEADER_LEN as u64 <= len {
            let magic = self.storage.read_at(offset, 8)?;
            if magic.as_slice() == SEGMENT_PAGE_MAGIC {
                if offset + DEFAULT_SEGMENT_PAGE_BYTES as u64 > len {
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
                    offset += DEFAULT_SEGMENT_PAGE_BYTES as u64;
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
        let magic = self.storage.read_at(offset, 8)?;
        if magic.as_slice() != SEGMENT_PAGE_MAGIC {
            return Err(Error::CorruptHeader);
        }
        let decoded = self.read_segment_page(offset)?;
        if let Some(leaf) = decoded
            .objects
            .iter()
            .find(|object| object.kind == SegmentObjectKind::FreeIndexLeaf)
        {
            return decode_free_index_leaf(&leaf.payload);
        }
        let Some(internal) = decoded
            .objects
            .iter()
            .find(|object| object.kind == SegmentObjectKind::FreeIndexInternal)
        else {
            return Err(Error::CorruptHeader);
        };
        let mut slots = Vec::new();
        for child in decode_free_index_internal(&internal.payload)? {
            slots.extend(self.read_free_index_slots(child.offset, depth + 1)?);
        }
        Ok(slots)
    }
}

fn object_kind_from_record_kind(kind: RecordKind) -> Result<SegmentObjectKind> {
    match kind {
        RecordKind::FileSegment => Ok(SegmentObjectKind::PackedFileData),
        RecordKind::Symlink => Ok(SegmentObjectKind::Symlink),
        RecordKind::Env => Ok(SegmentObjectKind::EnvSet),
        RecordKind::EnvDelete => Ok(SegmentObjectKind::EnvDelete),
        RecordKind::Delete => Ok(SegmentObjectKind::Delete),
        RecordKind::TocNode | RecordKind::CommitRoot | RecordKind::FreeIndex => {
            Err(Error::CorruptRecord)
        }
    }
}

fn record_kind_from_object_kind(kind: SegmentObjectKind) -> Result<RecordKind> {
    match kind {
        SegmentObjectKind::PackedFileData | SegmentObjectKind::FileData => {
            Ok(RecordKind::FileSegment)
        }
        SegmentObjectKind::Symlink => Ok(RecordKind::Symlink),
        SegmentObjectKind::EnvSet => Ok(RecordKind::Env),
        SegmentObjectKind::EnvDelete => Ok(RecordKind::EnvDelete),
        SegmentObjectKind::Delete => Ok(RecordKind::Delete),
        SegmentObjectKind::TocLeaf | SegmentObjectKind::TocInternal => Ok(RecordKind::TocNode),
        SegmentObjectKind::CommitRoot => Ok(RecordKind::CommitRoot),
        SegmentObjectKind::FreeIndexLeaf | SegmentObjectKind::FreeIndexInternal => {
            Ok(RecordKind::FreeIndex)
        }
        SegmentObjectKind::KeyDirectory => Err(Error::CorruptRecord),
    }
}

fn entry_record_slots(entry: &ManifestEntry) -> Vec<(u64, u64)> {
    if entry.record_len == 0 && entry.chunks.is_empty() {
        return Vec::new();
    }
    if entry.chunks.is_empty() {
        return vec![(entry.record_offset, entry.record_len)];
    }
    entry
        .chunks
        .iter()
        .map(|chunk| (chunk.record_offset, chunk.record_len))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_is_not_visible_in_cleartext() {
        let mut lb = Lockbox::create("secret");
        lb.put_file("/private/tax.pdf", b"1234").unwrap();
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
