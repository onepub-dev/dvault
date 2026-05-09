use super::Lockbox;
use crate::commit_root::{encode_commit_root, CommitRoot};
use crate::format::{
    encode_toc_internal, encode_toc_leaf, toc_child_groups, toc_leaf_groups, write_header,
    TocChild, TocInternal, TocLeaf, TocTreeNode,
};
use crate::free_index::{
    encode_free_index_internal, encode_free_index_leaf, free_index_child_groups,
    free_index_leaf_groups, FreeIndexChild,
};
use crate::host_path::HostPath;
use crate::key_directory::encode_key_directory;
use crate::segment_page::{SegmentObject, SegmentObjectKind};
use crate::storage::{Storage, StorageBackend};
use crate::{Error, LockboxOptions, Result};
use std::fs;
use std::path::Path;

impl Lockbox {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes().expect("failed to materialize lockbox bytes")
    }

    pub fn open_path(path: impl AsRef<Path>, key: impl AsRef<[u8]>) -> Result<Self> {
        Self::open_path_with_options(path, key, LockboxOptions::default())
    }

    pub fn open_path_with_options(
        path: impl AsRef<Path>,
        key: impl AsRef<[u8]>,
        options: LockboxOptions,
    ) -> Result<Self> {
        let path = HostPath::new(path);
        Self::open_storage(StorageBackend::file(path.as_path())?, key, options)
    }

    pub fn create_path(path: impl AsRef<Path>, key: impl AsRef<[u8]>) -> Result<Self> {
        Self::create_path_with_options(path, key, LockboxOptions::default())
    }

    pub fn create_path_with_options(
        path: impl AsRef<Path>,
        key: impl AsRef<[u8]>,
        options: LockboxOptions,
    ) -> Result<Self> {
        let path = HostPath::new(path);
        let mut bytes = vec![0; crate::constants::HEADER_LEN];
        let lockbox_id = crate::lockbox_id::LockboxId::new_random()?;
        write_header(&mut bytes, 0, 0, 0, lockbox_id);
        let mut lockbox = Self::open_storage(
            StorageBackend::create_file(path.as_path(), &bytes)?,
            key,
            options,
        )?;
        lockbox.lockbox_id = lockbox_id;
        Ok(lockbox)
    }

    pub fn write_to_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = HostPath::new(path);
        fs::write(path.as_path(), self.bytes()?).map_err(|err| Error::Io(err.to_string()))
    }

    pub fn commit(&mut self) -> Result<()> {
        let rollback = CommitRollback::capture(self);
        match self.commit_inner() {
            Ok(()) => Ok(()),
            Err(err) => {
                rollback.restore(self);
                Err(err)
            }
        }
    }

    fn commit_inner(&mut self) -> Result<()> {
        self.flush_pending_small_files()?;
        self.flush_pending_deletes()?;
        if self.needs_packing {
            self.pack_small_file_segments()?;
            self.needs_packing = false;
        }
        if self.toc_root.is_some() && self.dirty_toc_paths.is_empty() && self.key_slots.is_empty() {
            return Ok(());
        }
        let key_directory_generation = self.sequence.saturating_add(1);
        let key_directory_offsets = self.write_key_directory_mirrors(key_directory_generation)?;
        self.key_directory_offset = key_directory_offsets[0];
        self.key_directory_mirror_offsets = [key_directory_offsets[1], key_directory_offsets[2]];
        self.manifest_offset = self.commit_toc_btree()?;
        let manifest_offset = self.manifest_offset;
        self.free_index_offset = self.write_free_index()?;
        self.sequence += 1;
        let commit_root_payload = encode_commit_root(&CommitRoot {
            sequence: self.sequence,
            toc_root_offset: manifest_offset,
            free_index_root_offset: self.free_index_offset,
            key_directory_offset: self.key_directory_offset,
            key_directory_mirror_offsets: self.key_directory_mirror_offsets,
            key_directory_generation,
            previous_commit_root_offset: self.commit_root_offset,
            flags: 0,
        });
        self.commit_root_offset = self.append_commit_root_page(commit_root_payload)?;
        let sequence = self.sequence;
        let key_directory_offset = self.key_directory_offset;
        let lockbox_id = self.lockbox_id;
        let mut header = vec![0; crate::constants::HEADER_LEN];
        write_header(
            &mut header,
            self.commit_root_offset,
            sequence,
            key_directory_offset,
            lockbox_id,
        );
        self.storage.write_at(0, &header)?;
        Ok(())
    }

    fn write_key_directory_mirrors(&mut self, generation: u64) -> Result<[u64; 3]> {
        if self.key_slots.is_empty() {
            return Ok([0, 0, 0]);
        }
        let key_slots = self.key_slots.clone();
        let mut offsets = [0u64; 3];
        for (copy_index, offset) in offsets.iter_mut().enumerate() {
            let key_directory =
                encode_key_directory(&key_slots, self.lockbox_id, generation, copy_index as u32)?;
            *offset = self.storage.append(&key_directory)?;
        }
        Ok(offsets)
    }

    fn commit_toc_btree(&mut self) -> Result<u64> {
        if self.toc_root.is_some() && self.dirty_toc_paths.is_empty() {
            return Ok(self.manifest_offset);
        }
        let root = if self.toc_leaves.is_empty() {
            self.rebuild_toc_btree()?
        } else {
            self.write_incremental_toc_btree()?
        };
        self.dirty_toc_paths.clear();
        Ok(root)
    }

    fn rebuild_toc_btree(&mut self) -> Result<u64> {
        let mut entries = self.manifest.values().cloned().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        if entries.is_empty() {
            let offset = self.write_toc_leaf(&[])?;
            let leaf = TocLeaf {
                offset,
                entries: Vec::new(),
            };
            self.toc_root = Some(TocTreeNode::Leaf(leaf.clone()));
            self.toc_leaves = vec![leaf];
            return Ok(offset);
        }

        let mut leaves = Vec::new();
        for chunk in toc_leaf_groups(&entries)? {
            let offset = self.write_toc_leaf(chunk)?;
            leaves.push(TocLeaf {
                offset,
                entries: chunk.to_vec(),
            });
        }
        let root_node = self.write_toc_tree_for_leaves(&leaves)?;
        let root = root_node.offset();
        self.toc_root = Some(root_node);
        self.toc_leaves = leaves;
        Ok(root)
    }

    fn write_incremental_toc_btree(&mut self) -> Result<u64> {
        let dirty = std::mem::take(&mut self.dirty_toc_paths);
        let mut all_entries = self.manifest.values().cloned().collect::<Vec<_>>();
        all_entries.sort_by(|left, right| left.path.cmp(&right.path));

        let mut rebuilt_leaves = Vec::new();
        let mut cursor = 0usize;
        let old_leaves = std::mem::take(&mut self.toc_leaves);
        for (index, leaf) in old_leaves.iter().enumerate() {
            let Some(first) = leaf.entries.first().map(|entry| entry.path.as_str()) else {
                continue;
            };
            let next = old_leaves
                .get(index + 1)
                .and_then(|leaf| leaf.entries.first())
                .map(|entry| entry.path.as_str());
            while cursor < all_entries.len() && all_entries[cursor].path.as_str() < first {
                let chunk_start = cursor;
                cursor += 1;
                while cursor < all_entries.len()
                    && next.is_none_or(|next| all_entries[cursor].path.as_str() < next)
                    && dirty
                        .iter()
                        .all(|path| path.as_str() != all_entries[cursor].path.as_str())
                {
                    cursor += 1;
                }
                for chunk in toc_leaf_groups(&all_entries[chunk_start..cursor])? {
                    let offset = self.write_toc_leaf(chunk)?;
                    rebuilt_leaves.push(TocLeaf {
                        offset,
                        entries: chunk.to_vec(),
                    });
                }
            }

            let start = cursor;
            while cursor < all_entries.len()
                && next.is_none_or(|next| all_entries[cursor].path.as_str() < next)
            {
                cursor += 1;
            }
            let replacement_entries = &all_entries[start..cursor];
            let overlaps_dirty = replacement_entries.iter().any(|entry| {
                dirty.contains(&crate::logical_path::LogicalPath::from_canonical(
                    entry.path.clone(),
                ))
            }) || dirty
                .iter()
                .any(|path| path.as_str() >= first && next.is_none_or(|next| path.as_str() < next));
            let _should_consider_merge = overlaps_dirty
                && crate::toc_btree::toc_leaf_fill_percent(replacement_entries)
                    < crate::format::TOC_MIN_FILL_PERCENT;
            if !overlaps_dirty && same_leaf_entries(&leaf.entries, replacement_entries) {
                rebuilt_leaves.push(leaf.clone());
                continue;
            }
            for chunk in toc_leaf_groups(replacement_entries)? {
                let offset = self.write_toc_leaf(chunk)?;
                rebuilt_leaves.push(TocLeaf {
                    offset,
                    entries: chunk.to_vec(),
                });
            }
        }

        if cursor < all_entries.len() {
            for chunk in toc_leaf_groups(&all_entries[cursor..])? {
                let offset = self.write_toc_leaf(chunk)?;
                rebuilt_leaves.push(TocLeaf {
                    offset,
                    entries: chunk.to_vec(),
                });
            }
        }
        if rebuilt_leaves.is_empty() {
            let offset = self.write_toc_leaf(&[])?;
            rebuilt_leaves.push(TocLeaf {
                offset,
                entries: Vec::new(),
            });
        }
        rebuilt_leaves.sort_by(|left, right| leaf_first_path(left).cmp(leaf_first_path(right)));
        let root_node = if leaf_directory_is_compatible(&old_leaves, &rebuilt_leaves) {
            let old_root = self.toc_root.take().ok_or(Error::CorruptRecord)?;
            self.rewrite_compatible_toc_tree(old_root, &rebuilt_leaves)?
        } else {
            self.write_toc_tree_for_leaves(&rebuilt_leaves)?
        };
        let root = root_node.offset();
        self.toc_root = Some(root_node);
        self.toc_leaves = rebuilt_leaves;
        Ok(root)
    }

    fn write_toc_tree_for_leaves(&mut self, leaves: &[TocLeaf]) -> Result<TocTreeNode> {
        if leaves.len() == 1 {
            return Ok(TocTreeNode::Leaf(leaves[0].clone()));
        }
        let mut level = leaves
            .iter()
            .cloned()
            .map(TocTreeNode::Leaf)
            .collect::<Vec<_>>();

        while level.len() > 1 {
            let mut next_level = Vec::new();
            let children = level
                .iter()
                .map(|node| TocChild {
                    first_path: node.first_path().to_string(),
                    offset: node.offset(),
                })
                .collect::<Vec<_>>();
            for chunk in toc_child_groups(&children)? {
                let offset = self.write_toc_internal(chunk)?;
                let start = children
                    .iter()
                    .position(|child| child.first_path == chunk[0].first_path)
                    .ok_or(Error::CorruptRecord)?;
                let child_nodes = level[start..start + chunk.len()].to_vec();
                next_level.push(TocTreeNode::Internal(TocInternal {
                    offset,
                    children: child_nodes,
                }));
            }
            level = next_level;
        }

        Ok(level.remove(0))
    }

    fn rewrite_compatible_toc_tree(
        &mut self,
        node: TocTreeNode,
        new_leaves: &[TocLeaf],
    ) -> Result<TocTreeNode> {
        match node {
            TocTreeNode::Leaf(old_leaf) => {
                let Some(new_leaf) = new_leaves
                    .iter()
                    .find(|leaf| leaf_first_path(leaf) == leaf_first_path(&old_leaf))
                    .cloned()
                else {
                    return Err(Error::CorruptRecord);
                };
                Ok(TocTreeNode::Leaf(new_leaf))
            }
            TocTreeNode::Internal(old_internal) => {
                let mut changed = false;
                let mut children = Vec::with_capacity(old_internal.children.len());
                for child in &old_internal.children {
                    let rewritten = self.rewrite_compatible_toc_tree(child.clone(), new_leaves)?;
                    if rewritten.offset() != child.offset()
                        || rewritten.first_path() != child.first_path()
                    {
                        changed = true;
                    }
                    children.push(rewritten);
                }
                if !changed {
                    return Ok(TocTreeNode::Internal(old_internal));
                }
                let toc_children = children
                    .iter()
                    .map(|child| TocChild {
                        first_path: child.first_path().to_string(),
                        offset: child.offset(),
                    })
                    .collect::<Vec<_>>();
                let offset = self.write_toc_internal(&toc_children)?;
                Ok(TocTreeNode::Internal(TocInternal { offset, children }))
            }
        }
    }

    fn write_toc_leaf(&mut self, entries: &[crate::manifest_entry::ManifestEntry]) -> Result<u64> {
        let payload = encode_toc_leaf(entries)?;
        self.sequence += 1;
        self.append_toc_page(SegmentObjectKind::TocLeaf, payload)
    }

    fn write_toc_internal(&mut self, children: &[TocChild]) -> Result<u64> {
        let payload = encode_toc_internal(children)?;
        self.sequence += 1;
        self.append_toc_page(SegmentObjectKind::TocInternal, payload)
    }

    fn append_toc_page(&mut self, kind: SegmentObjectKind, payload: Vec<u8>) -> Result<u64> {
        let page_offset = self.allocate_segment_page_offset()?;
        let object = SegmentObject {
            kind,
            id: self.sequence,
            payload,
        };
        self.write_decoded_segment_page_at(page_offset, self.sequence, vec![object])?;
        Ok(page_offset)
    }

    fn write_free_index(&mut self) -> Result<u64> {
        let slots = self.free_space.slots_by_offset();
        if slots.is_empty() {
            return Ok(0);
        }
        self.sequence += 1;
        let mut level = Vec::new();
        for group in free_index_leaf_groups(&slots) {
            let offset = self.write_free_index_page(
                SegmentObjectKind::FreeIndexLeaf,
                encode_free_index_leaf(group),
            )?;
            level.push(FreeIndexChild {
                first_offset: group[0].offset,
                offset,
            });
        }
        while level.len() > 1 {
            let mut next = Vec::new();
            for group in free_index_child_groups(&level) {
                let offset = self.write_free_index_page(
                    SegmentObjectKind::FreeIndexInternal,
                    encode_free_index_internal(group),
                )?;
                next.push(FreeIndexChild {
                    first_offset: group[0].first_offset,
                    offset,
                });
            }
            level = next;
        }
        Ok(level[0].offset)
    }

    fn write_free_index_page(&mut self, kind: SegmentObjectKind, payload: Vec<u8>) -> Result<u64> {
        let page_offset = self.storage.len()?;
        let object = SegmentObject {
            kind,
            id: self.sequence,
            payload,
        };
        self.write_decoded_segment_page_at(page_offset, self.sequence, vec![object])?;
        Ok(page_offset)
    }

    fn append_commit_root_page(&mut self, payload: Vec<u8>) -> Result<u64> {
        let page_offset = self.storage.len()?;
        let object = SegmentObject {
            kind: SegmentObjectKind::CommitRoot,
            id: self.sequence,
            payload,
        };
        self.write_decoded_segment_page_at(page_offset, self.sequence, vec![object])?;
        Ok(page_offset)
    }
}

struct CommitRollback {
    sequence: u64,
    commit_root_offset: u64,
    manifest_offset: u64,
    free_index_offset: u64,
    key_directory_offset: u64,
    key_directory_mirror_offsets: [u64; 2],
    key_slots: Vec<crate::key_slot::KeySlot>,
    manifest: std::collections::BTreeMap<
        crate::logical_path::LogicalPath,
        crate::manifest_entry::ManifestEntry,
    >,
    toc_root: Option<TocTreeNode>,
    toc_leaves: Vec<TocLeaf>,
    dirty_toc_paths: std::collections::BTreeSet<crate::logical_path::LogicalPath>,
    env_vars: Option<std::collections::BTreeMap<String, String>>,
    free_space: crate::free_slot::FreeSpace,
    record_ref_counts: std::collections::HashMap<u64, usize, crate::fast_hash::FastBuildHasher>,
    pending_small_files: std::collections::BTreeMap<String, crate::file_chunk::PendingFileChunk>,
    pending_deletes: Vec<String>,
    needs_packing: bool,
}

impl CommitRollback {
    fn capture(lockbox: &Lockbox) -> Self {
        Self {
            sequence: lockbox.sequence,
            commit_root_offset: lockbox.commit_root_offset,
            manifest_offset: lockbox.manifest_offset,
            free_index_offset: lockbox.free_index_offset,
            key_directory_offset: lockbox.key_directory_offset,
            key_directory_mirror_offsets: lockbox.key_directory_mirror_offsets,
            key_slots: lockbox.key_slots.clone(),
            manifest: lockbox.manifest.clone(),
            toc_root: lockbox.toc_root.clone(),
            toc_leaves: lockbox.toc_leaves.clone(),
            dirty_toc_paths: lockbox.dirty_toc_paths.clone(),
            env_vars: lockbox.env_vars.borrow().clone(),
            free_space: lockbox.free_space.clone(),
            record_ref_counts: lockbox.record_ref_counts.clone(),
            pending_small_files: lockbox.pending_small_files.clone(),
            pending_deletes: lockbox.pending_deletes.clone(),
            needs_packing: lockbox.needs_packing,
        }
    }

    fn restore(self, lockbox: &mut Lockbox) {
        lockbox.sequence = self.sequence;
        lockbox.commit_root_offset = self.commit_root_offset;
        lockbox.manifest_offset = self.manifest_offset;
        lockbox.free_index_offset = self.free_index_offset;
        lockbox.key_directory_offset = self.key_directory_offset;
        lockbox.key_directory_mirror_offsets = self.key_directory_mirror_offsets;
        lockbox.key_slots = self.key_slots;
        lockbox.manifest = self.manifest;
        lockbox.toc_root = self.toc_root;
        lockbox.toc_leaves = self.toc_leaves;
        lockbox.dirty_toc_paths = self.dirty_toc_paths;
        lockbox.env_vars.replace(self.env_vars);
        lockbox.free_space = self.free_space;
        lockbox.record_ref_counts = self.record_ref_counts;
        lockbox.pending_small_files = self.pending_small_files;
        lockbox.pending_deletes = self.pending_deletes;
        lockbox.needs_packing = self.needs_packing;
        lockbox.segment_manager.borrow_mut().clear();
    }
}

fn same_leaf_entries(
    old: &[crate::manifest_entry::ManifestEntry],
    new: &[crate::manifest_entry::ManifestEntry],
) -> bool {
    old.len() == new.len()
        && old.iter().zip(new).all(|(old, new)| {
            old.path == new.path
                && old.record_offset == new.record_offset
                && old.record_len == new.record_len
                && old.deleted == new.deleted
        })
}

fn leaf_first_path(leaf: &TocLeaf) -> &str {
    leaf.entries
        .first()
        .map(|entry| entry.path.as_str())
        .unwrap_or("")
}

fn leaf_directory_is_compatible(old: &[TocLeaf], new: &[TocLeaf]) -> bool {
    old.len() == new.len()
        && old
            .iter()
            .zip(new)
            .all(|(old, new)| leaf_first_path(old) == leaf_first_path(new))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_FILE_PERMISSIONS;
    use crate::file_chunk::{FileChunk, FileFragment};
    use crate::logical_path::LogicalPath;
    use crate::manifest_entry::ManifestEntry;
    use crate::node_kind::NodeKind;
    use crate::segment_page::DEFAULT_SEGMENT_PAGE_BYTES;

    #[test]
    fn compatible_toc_update_rewrites_only_changed_leaf_and_ancestors() {
        let mut lb = Lockbox::create("secret");
        for entry in synthetic_manifest_entries(40_000) {
            lb.manifest
                .insert(LogicalPath::from_canonical(entry.path.clone()), entry);
        }
        lb.commit().unwrap();
        let len_after_create = lb.to_bytes().len();
        let root_after_create = lb.manifest_offset;
        let old_leaf_offsets = lb
            .toc_leaves
            .iter()
            .map(|leaf| leaf.offset)
            .collect::<Vec<_>>();
        assert!(old_leaf_offsets.len() > 1);

        let path = "/toc-cow/file-00001.txt";
        let entry = lb.manifest.get_mut(path).unwrap();
        entry.record_offset += 1;
        lb.mark_toc_dirty(path);
        lb.commit().unwrap();
        let new_leaf_offsets = lb
            .toc_leaves
            .iter()
            .map(|leaf| leaf.offset)
            .collect::<Vec<_>>();

        assert_ne!(lb.manifest_offset, root_after_create);
        assert_eq!(old_leaf_offsets.len(), new_leaf_offsets.len());
        assert!(
            old_leaf_offsets
                .iter()
                .zip(&new_leaf_offsets)
                .filter(|(old, new)| old != new)
                .count()
                <= 1
        );
        assert!(lb.to_bytes().len() > len_after_create);
    }

    #[test]
    fn noop_commit_reuses_existing_toc_root() {
        let mut lb = Lockbox::create("secret");
        for entry in synthetic_manifest_entries(100) {
            lb.manifest
                .insert(LogicalPath::from_canonical(entry.path.clone()), entry);
        }
        lb.commit().unwrap();
        let root = lb.manifest_offset;
        let len = lb.to_bytes().len();

        lb.commit().unwrap();

        assert_eq!(lb.manifest_offset, root);
        assert_eq!(lb.to_bytes().len(), len);
    }

    #[test]
    fn header_points_to_commit_root_that_points_to_toc_root() {
        let mut lb = Lockbox::create("secret");
        lb.put_file("/docs/a.txt", b"alpha").unwrap();
        lb.commit().unwrap();

        let bytes = lb.to_bytes();
        let (header_root_offset, _, _, _) = crate::format::read_header(&bytes).unwrap();
        assert_eq!(header_root_offset, lb.commit_root_offset);
        assert_ne!(header_root_offset, lb.manifest_offset);

        let page = &bytes
            [header_root_offset as usize..header_root_offset as usize + DEFAULT_SEGMENT_PAGE_BYTES];
        let decoded =
            crate::segment_page::decode_segment_page(page, lb.lockbox_id, lb.key.expose()).unwrap();
        let commit_object = decoded
            .objects
            .iter()
            .find(|object| object.kind == SegmentObjectKind::CommitRoot)
            .unwrap();
        let commit_root = crate::commit_root::decode_commit_root(&commit_object.payload).unwrap();
        assert_eq!(commit_root.toc_root_offset, lb.manifest_offset);
    }

    #[test]
    fn committed_toc_is_live_only_after_delete() {
        let mut lb = Lockbox::create("secret");
        lb.put_file("/docs/a.txt", b"alpha").unwrap();
        lb.put_file("/docs/b.txt", b"bravo").unwrap();
        lb.commit().unwrap();

        lb.delete("/docs/a.txt").unwrap();
        lb.commit().unwrap();

        let reopened = Lockbox::open(lb.to_bytes(), "secret").unwrap();
        assert!(!reopened.manifest.contains_key("/docs/a.txt"));
        assert!(reopened.manifest.contains_key("/docs/b.txt"));
        assert!(reopened
            .toc_leaves
            .iter()
            .flat_map(|leaf| leaf.entries.iter())
            .all(|entry| !entry.deleted && entry.path != "/docs/a.txt"));
    }

    #[test]
    fn commit_root_restores_persisted_free_index_on_open() {
        let mut lb = Lockbox::create("secret");
        let mut state = 0x1234_5678u64;
        let data = (0..(6 * 1024 * 1024))
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                (state >> 32) as u8
            })
            .collect::<Vec<_>>();
        for index in 0..6 {
            lb.put_file(&format!("/docs/remove-{index}.bin"), &data)
                .unwrap();
        }
        lb.commit().unwrap();
        for index in 0..6 {
            lb.delete(&format!("/docs/remove-{index}.bin")).unwrap();
        }
        lb.commit().unwrap();

        assert!(lb.free_index_offset > 0);
        assert!(!lb.free_space.slots_by_offset().is_empty());
        let bytes = lb.to_bytes();
        assert_eq!(
            &bytes[lb.free_index_offset as usize..lb.free_index_offset as usize + 8],
            crate::segment_page::SEGMENT_PAGE_MAGIC
        );
        let reopened = Lockbox::open(bytes, "secret").unwrap();
        assert!(!reopened.free_space.slots_by_offset().is_empty());
    }

    #[test]
    fn free_index_overflow_writes_internal_nodes_and_reopens() {
        let mut lb = Lockbox::create("secret");
        let mut state = 0x1234_5678u64;
        let data = (0..(2 * 1024 * 1024))
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                (state >> 32) as u8
            })
            .collect::<Vec<_>>();
        for index in 0..((crate::free_index::FREE_INDEX_LEAF_SLOT_CAPACITY + 3) * 2) {
            lb.put_file(&format!("/docs/free-index-{index}.bin"), &data)
                .unwrap();
        }
        lb.commit().unwrap();
        for index in (0..((crate::free_index::FREE_INDEX_LEAF_SLOT_CAPACITY + 3) * 2)).step_by(2) {
            lb.delete(&format!("/docs/free-index-{index}.bin")).unwrap();
        }
        lb.commit().unwrap();
        assert!(lb.free_index_offset > 0);
        let bytes = lb.to_bytes();
        let root_page = &bytes[lb.free_index_offset as usize
            ..lb.free_index_offset as usize + crate::segment_page::DEFAULT_SEGMENT_PAGE_BYTES];
        let decoded =
            crate::segment_page::decode_segment_page(root_page, lb.lockbox_id, lb.key.expose())
                .unwrap();
        assert!(decoded
            .objects
            .iter()
            .any(|object| object.kind == SegmentObjectKind::FreeIndexInternal));

        let reopened = Lockbox::open(bytes, "secret").unwrap();
        assert!(
            reopened.free_space.slots_by_offset().len()
                > crate::free_index::FREE_INDEX_LEAF_SLOT_CAPACITY
        );
    }

    #[test]
    fn failed_commit_after_partial_appends_reopens_previous_commit() {
        let mut lb = Lockbox::create("secret");
        lb.put_file("/docs/old.txt", b"old").unwrap();
        lb.commit().unwrap();

        lb.put_file("/docs/new.txt", b"new").unwrap();
        lb.storage.fail_memory_append_after_successes(1);
        assert!(matches!(lb.commit(), Err(Error::Io(_))));

        assert_eq!(lb.get_file("/docs/new.txt").unwrap(), b"new");
        let reopened = Lockbox::open(lb.to_bytes(), "secret").unwrap();
        assert_eq!(reopened.get_file("/docs/old.txt").unwrap(), b"old");
        assert!(matches!(
            reopened.get_file("/docs/new.txt"),
            Err(Error::NotFound(_))
        ));

        lb.commit().unwrap();
        let reopened = Lockbox::open(lb.to_bytes(), "secret").unwrap();
        assert_eq!(reopened.get_file("/docs/new.txt").unwrap(), b"new");
    }

    #[test]
    fn failed_commit_header_publish_reopens_previous_commit() {
        let mut lb = Lockbox::create("secret");
        lb.put_file("/docs/old.txt", b"old").unwrap();
        lb.commit().unwrap();

        lb.put_file("/docs/new.txt", b"new").unwrap();
        lb.storage.fail_memory_next_write_at(0);
        assert!(matches!(lb.commit(), Err(Error::Io(_))));

        assert_eq!(lb.get_file("/docs/new.txt").unwrap(), b"new");
        let reopened = Lockbox::open(lb.to_bytes(), "secret").unwrap();
        assert_eq!(reopened.get_file("/docs/old.txt").unwrap(), b"old");
        assert!(matches!(
            reopened.get_file("/docs/new.txt"),
            Err(Error::NotFound(_))
        ));

        lb.commit().unwrap();
        let reopened = Lockbox::open(lb.to_bytes(), "secret").unwrap();
        assert_eq!(reopened.get_file("/docs/new.txt").unwrap(), b"new");
    }

    fn synthetic_manifest_entries(count: usize) -> Vec<ManifestEntry> {
        (0..count)
            .map(|i| ManifestEntry {
                path: format!("/toc-cow/file-{i:05}.txt"),
                len: 1,
                record_offset: 1_000_000 + i as u64,
                record_len: 64,
                deleted: false,
                node_kind: NodeKind::File,
                permissions: DEFAULT_FILE_PERMISSIONS,
                symlink_target: None,
                chunks: (0..8)
                    .map(|chunk| FileChunk {
                        file_offset: chunk as u64,
                        len: 1,
                        compressed_len: 1,
                        compression: crate::compression::COMPRESSION_NONE,
                        frame_id: 3_000_000 + (i * 8 + chunk) as u64,
                        fragments: vec![FileFragment {
                            page_offset: 2_000_000 + (i * 8 + chunk) as u64,
                            page_len: DEFAULT_SEGMENT_PAGE_BYTES as u64,
                            object_id: 4_000_000 + (i * 8 + chunk) as u64,
                            fragment_offset: 0,
                            fragment_len: 1,
                        }],
                    })
                    .collect(),
            })
            .collect()
    }
}
