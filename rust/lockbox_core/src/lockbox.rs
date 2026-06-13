use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::commit_auth::{commit_auth_digest, commit_auth_message, decode_commit_auth, CommitAuth};
use crate::commit_root::decode_commit_root;
use crate::compression_frame_manifest::CompressionFrameSlice;
use crate::constants::HEADER_LEN;
use crate::fast_hash::FastBuildHasher;
use crate::file_chunk::PendingFileChunk;
use crate::file_format::{
    decode_toc_node, read_header, write_header, TocInternal, TocLeaf, TocNode, TocTreeNode,
};
use crate::form_btree::{FormLeaf, FormTreeNode};
use crate::free_index::{decode_free_index_internal, decode_free_index_leaf};
use crate::free_slot::{FreeSlot, FreeSpace};
use crate::key_directory::{
    best_key_directory, decode_key_directory_decoded_page, scan_key_directories,
    DecodedKeyDirectory,
};
use crate::key_slot::{KeySlot, LockboxKeySlot};
use crate::lockbox_id::LockboxId;
use crate::lockbox_path::LockboxPath;
use crate::page::{
    page_size_for_encoded_objects, page_size_for_objects, physical_page_size_from_page_slice,
    DecodedPage, PageObject, PageObjectKind, DEFAULT_METADATA_PAGE_BYTES, PAGE_MAGIC,
};
use crate::page_cache::{PageCache, PageReadKey, PageSecurity, PageWritePolicy};
use crate::record::{DecodedRecord, RecordHeader, RecordKind};
use crate::secret_vec::SecretVec;
use crate::signing::{verify_commit_signatures, OwnerSigningKeyPair};
use crate::storage::{Storage, StorageBackend};
use crate::toc_entry::TocEntry;
use crate::variable_btree::{VariableLeaf, VariableTreeNode, VariableValue};
use crate::{
    CacheStats, Error, FormDefinition, FormRecord, LockboxOptions, RecoveryReport, Result,
    VariableName, WorkerPolicy, WorkloadProfile,
};
use zeroize::{Zeroize, Zeroizing};

mod commit;
mod extraction;
mod files;
mod forms;
mod key_management;
mod listing;
mod mutation;
mod recovery;
mod symlinks;
mod variables;

#[cfg(feature = "vault-bridge")]
pub use key_management::UnlockedContentKey;
pub use key_management::{LockboxProtection, LockboxUnlock};
pub use recovery::RecoveryScanner;
pub use variables::VariableValueRef;

/// Read-only diagnostics for an opened lockbox.
///
/// The inspector intentionally exposes no mutation methods. It is a separate
/// handle so page/cache details do not sit on the main high-level `Lockbox`
/// API.
pub struct LockboxInspector<'a> {
    lockbox: &'a Lockbox,
}

/// Public metadata read from a lockbox file without decrypting its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockboxFileInspection {
    /// Stable id embedded in this lockbox.
    pub lockbox_id: LockboxId,
    /// Whether the primary public header was readable and authenticated.
    pub header_readable: bool,
    /// Best key-directory generation found in the lockbox file.
    pub key_directory_generation: u64,
    /// Number of readable key-directory copies found for this lockbox.
    pub key_directory_copy_count: usize,
    /// Public key-slot metadata for access methods stored in the lockbox.
    pub key_slots: Vec<LockboxKeySlot>,
    /// Whether the public header points at signed owner commit metadata.
    pub owner_signed: bool,
}

#[derive(Debug, Default)]
pub(crate) struct CompressionFrameCache {
    pub(crate) entries: BTreeMap<u64, CachedCompressionFrame>,
    pub(crate) used_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct CachedCompressionFrame {
    pub(crate) compression: u8,
    pub(crate) compression_frame_len: u64,
    pub(crate) compressed_len: u64,
    pub(crate) compression_frame_digest: [u8; 32],
    pub(crate) slices: Vec<CompressionFrameSlice>,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Coarse import pipeline timing counters.
///
/// These counters are intended for benchmark diagnostics. They are cumulative
/// for the current `Lockbox` handle until `reset_import_stats` is called.
pub struct ImportStats {
    /// Host filesystem metadata/stat calls, in nanoseconds.
    pub host_stat_nanos: u128,
    /// Host filesystem reads, including streamed chunk reads, in nanoseconds.
    pub host_read_nanos: u128,
    /// Compression-frame payload assembly and compression, in nanoseconds.
    pub frame_prepare_nanos: u128,
    /// Page/object encoding and storage writes, in nanoseconds.
    pub page_write_nanos: u128,
}

impl Drop for CachedCompressionFrame {
    fn drop(&mut self) {
        self.data.zeroize();
    }
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
    commit_auth_offset: u64,
    commit_auth_digest: [u8; 32],
    toc_root_offset: u64,
    variable_root_offset: u64,
    form_root_offset: u64,
    free_index_offset: u64,
    key_directory_offset: u64,
    key_directory_mirror_offsets: [u64; 2],
    key_directory_generation: u64,
    dirty_key_directory: bool,
    lockbox_id: LockboxId,
    read_only: bool,
    owner_signing_key: Option<OwnerSigningKeyPair>,
    key_slots: Vec<KeySlot>,
    toc_entries: BTreeMap<LockboxPath, TocEntry>,
    toc_root: Option<TocTreeNode>,
    toc_leaves: Vec<TocLeaf>,
    dirty_toc_paths: BTreeSet<LockboxPath>,
    variables: RefCell<Option<BTreeMap<VariableName, VariableValue>>>,
    variable_root: Option<VariableTreeNode>,
    variable_leaves: Vec<VariableLeaf>,
    dirty_variables: bool,
    form_definitions: RefCell<Option<BTreeMap<String, FormDefinition>>>,
    form_records: RefCell<Option<BTreeMap<LockboxPath, FormRecord>>>,
    form_root: Option<FormTreeNode>,
    form_leaves: Vec<FormLeaf>,
    dirty_form_keys: BTreeSet<String>,
    dirty_forms: bool,
    page_manager: RefCell<PageCache>,
    compression_frame_cache: RefCell<CompressionFrameCache>,
    import_stats: RefCell<ImportStats>,
    workload_profile: WorkloadProfile,
    worker_policy: WorkerPolicy,
    free_space: FreeSpace,
    record_ref_counts: std::collections::HashMap<u64, usize, FastBuildHasher>,
    pending_redactions: BTreeMap<u64, PendingRedaction>,
    redacted_free_slots: Vec<FreeSlot>,
    pending_small_files: BTreeMap<LockboxPath, PendingFileChunk>,
    pending_small_file_bytes: usize,
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
            commit_auth_offset: self.commit_auth_offset,
            commit_auth_digest: self.commit_auth_digest,
            toc_root_offset: self.toc_root_offset,
            variable_root_offset: self.variable_root_offset,
            form_root_offset: self.form_root_offset,
            free_index_offset: self.free_index_offset,
            key_directory_offset: self.key_directory_offset,
            key_directory_mirror_offsets: self.key_directory_mirror_offsets,
            key_directory_generation: self.key_directory_generation,
            dirty_key_directory: self.dirty_key_directory,
            lockbox_id: self.lockbox_id,
            read_only: self.read_only,
            owner_signing_key: self
                .owner_signing_key
                .as_ref()
                .map(OwnerSigningKeyPair::try_clone)
                .transpose()?,
            key_slots: self.key_slots.clone(),
            toc_entries: self.toc_entries.clone(),
            toc_root: self.toc_root.clone(),
            toc_leaves: self.toc_leaves.clone(),
            dirty_toc_paths: self.dirty_toc_paths.clone(),
            variables: RefCell::new(self.variables.borrow().clone()),
            variable_root: self.variable_root.clone(),
            variable_leaves: self.variable_leaves.clone(),
            dirty_variables: self.dirty_variables,
            form_definitions: RefCell::new(self.form_definitions.borrow().clone()),
            form_records: RefCell::new(self.form_records.borrow().clone()),
            form_root: self.form_root.clone(),
            form_leaves: self.form_leaves.clone(),
            dirty_form_keys: self.dirty_form_keys.clone(),
            dirty_forms: self.dirty_forms,
            page_manager: RefCell::new(self.page_manager.borrow().clone()),
            compression_frame_cache: RefCell::new(CompressionFrameCache::default()),
            import_stats: RefCell::new(ImportStats::default()),
            workload_profile: self.workload_profile,
            worker_policy: self.worker_policy,
            free_space: self.free_space.clone(),
            record_ref_counts: self.record_ref_counts.clone(),
            pending_redactions: self.pending_redactions.clone(),
            redacted_free_slots: self.redacted_free_slots.clone(),
            pending_small_files: self.pending_small_files.clone(),
            pending_small_file_bytes: self.pending_small_file_bytes,
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
        write_header(&mut bytes, 0, 0, 0, lockbox_id, 0);
        Self {
            storage: StorageBackend::memory(bytes),
            key,
            sequence: 0,
            commit_root_offset: 0,
            commit_auth_offset: 0,
            commit_auth_digest: [0; 32],
            toc_root_offset: 0,
            variable_root_offset: 0,
            form_root_offset: 0,
            free_index_offset: 0,
            key_directory_offset: 0,
            key_directory_mirror_offsets: [0, 0],
            key_directory_generation: 0,
            dirty_key_directory: false,
            lockbox_id,
            read_only: false,
            owner_signing_key: Some(
                OwnerSigningKeyPair::generate().expect("system random source failed"),
            ),
            key_slots: Vec::new(),
            toc_entries: BTreeMap::new(),
            toc_root: None,
            toc_leaves: Vec::new(),
            dirty_toc_paths: BTreeSet::new(),
            variables: RefCell::new(Some(BTreeMap::new())),
            variable_root: None,
            variable_leaves: Vec::new(),
            dirty_variables: false,
            form_definitions: RefCell::new(Some(BTreeMap::new())),
            form_records: RefCell::new(Some(BTreeMap::new())),
            form_root: None,
            form_leaves: Vec::new(),
            dirty_form_keys: BTreeSet::new(),
            dirty_forms: false,
            page_manager: RefCell::new(PageCache::new(options.cache_limit)),
            compression_frame_cache: RefCell::new(CompressionFrameCache::default()),
            import_stats: RefCell::new(ImportStats::default()),
            workload_profile: options.workload_profile,
            worker_policy: options.worker_policy,
            free_space: FreeSpace::default(),
            record_ref_counts: std::collections::HashMap::with_hasher(FastBuildHasher::default()),
            pending_redactions: BTreeMap::new(),
            redacted_free_slots: Vec::new(),
            pending_small_files: BTreeMap::new(),
            pending_small_file_bytes: 0,
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
        let (
            header_root_offset,
            header_auth_offset,
            sequence,
            header_key_directory_offset,
            lockbox_id,
        ) = match header_result {
            Ok(header) => (
                header.commit_root_offset,
                header.commit_auth_offset,
                header.sequence,
                header.key_directory_offset,
                header.lockbox_id,
            ),
            Err(_) => {
                let Some(key_directory) = scanned_key_directory.as_ref() else {
                    return Err(Error::CorruptHeader);
                };
                (0, 0, 0, key_directory.offset, key_directory.lockbox_id)
            }
        };
        let mut lockbox = Self {
            storage,
            key,
            sequence,
            commit_root_offset: 0,
            commit_auth_offset: 0,
            commit_auth_digest: [0; 32],
            toc_root_offset: 0,
            variable_root_offset: 0,
            form_root_offset: 0,
            free_index_offset: 0,
            key_directory_offset: header_key_directory_offset,
            key_directory_mirror_offsets: [0, 0],
            key_directory_generation: 0,
            dirty_key_directory: false,
            lockbox_id,
            read_only: false,
            owner_signing_key: None,
            key_slots: Vec::new(),
            toc_entries: BTreeMap::new(),
            toc_root: None,
            toc_leaves: Vec::new(),
            dirty_toc_paths: BTreeSet::new(),
            variables: RefCell::new(None),
            variable_root: None,
            variable_leaves: Vec::new(),
            dirty_variables: false,
            form_definitions: RefCell::new(None),
            form_records: RefCell::new(None),
            form_root: None,
            form_leaves: Vec::new(),
            dirty_form_keys: BTreeSet::new(),
            dirty_forms: false,
            page_manager: RefCell::new(PageCache::new(options.cache_limit)),
            compression_frame_cache: RefCell::new(CompressionFrameCache::default()),
            import_stats: RefCell::new(ImportStats::default()),
            workload_profile: options.workload_profile,
            worker_policy: options.worker_policy,
            free_space: FreeSpace::default(),
            record_ref_counts: std::collections::HashMap::with_hasher(FastBuildHasher::default()),
            pending_redactions: BTreeMap::new(),
            redacted_free_slots: Vec::new(),
            pending_small_files: BTreeMap::new(),
            pending_small_file_bytes: 0,
            pending_symlinks: BTreeMap::new(),
            needs_packing: false,
        };

        let mut toc_root_offset = header_root_offset;
        if header_auth_offset > 0 {
            let Some((auth_offset, auth_digest, auth, commit_root)) =
                lockbox.find_valid_commit_from_auth_chain(header_auth_offset)?
            else {
                return Err(Error::CorruptRecord);
            };
            lockbox.commit_auth_offset = auth_offset;
            lockbox.commit_auth_digest = auth_digest;
            lockbox.commit_root_offset = auth.commit_root_offset;
            lockbox.sequence = commit_root.sequence;
            lockbox.key_directory_offset = commit_root.key_directory_offset;
            lockbox.key_directory_mirror_offsets = commit_root.key_directory_mirror_offsets;
            lockbox.key_directory_generation = commit_root.key_directory_generation;
            lockbox.free_index_offset = commit_root.free_index_root_offset;
            lockbox.variable_root_offset = commit_root.variable_root_offset;
            lockbox.form_root_offset = commit_root.form_root_offset;
            toc_root_offset = commit_root.toc_root_offset;
        } else if header_root_offset > 0 {
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
            lockbox.variable_root_offset = commit_root.variable_root_offset;
            lockbox.form_root_offset = commit_root.form_root_offset;
            toc_root_offset = commit_root.toc_root_offset;
        } else if let Some((offset, commit_root)) = lockbox.find_latest_valid_commit_root()? {
            lockbox.commit_root_offset = offset;
            lockbox.sequence = commit_root.sequence;
            lockbox.key_directory_offset = commit_root.key_directory_offset;
            lockbox.key_directory_mirror_offsets = commit_root.key_directory_mirror_offsets;
            lockbox.key_directory_generation = commit_root.key_directory_generation;
            lockbox.free_index_offset = commit_root.free_index_root_offset;
            lockbox.variable_root_offset = commit_root.variable_root_offset;
            lockbox.form_root_offset = commit_root.form_root_offset;
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

    /// Inspect public lockbox metadata without decrypting stored contents.
    ///
    /// This reads the lockbox header and key directory only. It does not unlock
    /// file contents and does not require a password, recipient private key, or
    /// cached content key.
    pub fn inspect_file(path: impl AsRef<Path>) -> Result<LockboxFileInspection> {
        let storage = StorageBackend::file(path.as_ref())?;
        let header = storage.read_at(0, HEADER_LEN)?;
        let header_result = read_header(&header);
        let directories =
            key_management::key_directories_from_storage(&storage).unwrap_or_default();

        if let Ok(header) = header_result {
            let matching_directories = directories
                .into_iter()
                .filter(|directory| directory.lockbox_id == header.lockbox_id)
                .collect::<Vec<_>>();
            let best = matching_directories.first();
            return Ok(LockboxFileInspection {
                lockbox_id: header.lockbox_id,
                header_readable: true,
                key_directory_generation: best.map(|directory| directory.generation).unwrap_or(0),
                key_directory_copy_count: matching_directories.len(),
                key_slots: best
                    .map(|directory| directory.slots.iter().map(KeySlot::info).collect())
                    .unwrap_or_default(),
                owner_signed: header.commit_auth_offset != 0,
            });
        }

        let directories = key_management::key_directories_from_storage(&storage)?;
        let Some(best) = directories.first() else {
            return Err(Error::CorruptHeader);
        };
        Ok(LockboxFileInspection {
            lockbox_id: best.lockbox_id,
            header_readable: false,
            key_directory_generation: best.generation,
            key_directory_copy_count: directories
                .iter()
                .filter(|directory| directory.lockbox_id == best.lockbox_id)
                .count(),
            key_slots: best.slots.iter().map(KeySlot::info).collect(),
            owner_signed: false,
        })
    }

    pub(crate) fn mark_read_only(&mut self) {
        self.read_only = true;
    }

    pub fn set_owner_signing_key(&mut self, keypair: OwnerSigningKeyPair) {
        self.owner_signing_key = Some(keypair);
    }

    /// Set cache behavior tuned for the caller's expected access pattern.
    pub fn set_workload_profile(&mut self, profile: WorkloadProfile) {
        self.workload_profile = profile;
    }

    /// Return the currently selected workload profile.
    pub fn workload_profile(&self) -> WorkloadProfile {
        self.workload_profile
    }

    /// Set the worker policy used for native page/frame preparation.
    pub fn set_worker_policy(&mut self, policy: WorkerPolicy) {
        self.worker_policy = policy;
    }

    /// Return the currently selected worker policy.
    pub fn worker_policy(&self) -> WorkerPolicy {
        self.worker_policy
    }

    pub(crate) fn worker_jobs(&self) -> usize {
        self.worker_policy.effective_jobs()
    }

    /// Reset import diagnostic counters.
    pub fn reset_import_stats(&self) {
        *self.import_stats.borrow_mut() = ImportStats::default();
    }

    /// Return cumulative import diagnostic counters for this handle.
    pub fn import_stats(&self) -> ImportStats {
        *self.import_stats.borrow()
    }

    pub(crate) fn add_host_stat_nanos(&self, nanos: u128) {
        self.import_stats.borrow_mut().host_stat_nanos += nanos;
    }

    pub(crate) fn add_host_read_nanos(&self, nanos: u128) {
        self.import_stats.borrow_mut().host_read_nanos += nanos;
    }

    pub(crate) fn add_frame_prepare_nanos(&self, nanos: u128) {
        self.import_stats.borrow_mut().frame_prepare_nanos += nanos;
    }

    pub(crate) fn add_page_write_nanos(&self, nanos: u128) {
        self.import_stats.borrow_mut().page_write_nanos += nanos;
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

    pub(crate) fn read_and_verify_commit_auth_at(
        &self,
        offset: u64,
    ) -> Result<(CommitAuth, [u8; 32])> {
        let payload = self.read_commit_auth_payload_at(offset)?;
        let digest = commit_auth_digest(&payload);
        let auth = decode_commit_auth(&payload)?;
        if auth.lockbox_id != self.lockbox_id {
            return Err(Error::CorruptRecord);
        }
        let message = commit_auth_message(&auth)?;
        verify_commit_signatures(&message, &auth.signatures)?;
        Ok((auth, digest))
    }

    pub(crate) fn find_valid_commit_from_auth_chain(
        &self,
        mut offset: u64,
    ) -> Result<Option<(u64, [u8; 32], CommitAuth, crate::commit_root::CommitRoot)>> {
        let mut expected_digest = None;
        while offset != 0 {
            let Ok((auth, digest)) = self.read_and_verify_commit_auth_at(offset) else {
                return Ok(None);
            };
            if let Some(expected) = expected_digest {
                if digest != expected {
                    return Ok(None);
                }
            }
            if let Ok(root) = self.read_verified_commit_root_from_auth(&auth) {
                return Ok(Some((offset, digest, auth, root)));
            }
            if auth.previous_auth_offset == 0 {
                return Ok(None);
            }
            expected_digest = Some(auth.previous_auth_digest);
            offset = auth.previous_auth_offset;
        }
        Ok(None)
    }

    pub(crate) fn read_verified_commit_root_from_auth(
        &self,
        auth: &CommitAuth,
    ) -> Result<crate::commit_root::CommitRoot> {
        let payload = self.read_commit_root_payload_at(auth.commit_root_offset)?;
        if crate::crypto::strong_checksum(&payload) != auth.commit_root_digest {
            return Err(Error::CorruptRecord);
        }
        let root = decode_commit_root(&payload)?;
        if root.sequence != auth.sequence {
            return Err(Error::CorruptRecord);
        }
        Ok(root)
    }

    pub(crate) fn read_commit_root_payload_at(&self, offset: u64) -> Result<Vec<u8>> {
        self.with_page(offset, |page| {
            let object = page
                .objects
                .iter()
                .find(|object| object.kind == PageObjectKind::CommitRoot)
                .ok_or(Error::CorruptRecord)?;
            object.with_payload(|payload| payload.to_vec())
        })
    }

    pub(crate) fn read_commit_auth_payload_at(&self, offset: u64) -> Result<Vec<u8>> {
        self.with_page(offset, |page| {
            let object = page
                .objects
                .iter()
                .find(|object| object.kind == PageObjectKind::CommitAuth)
                .ok_or(Error::CorruptRecord)?;
            object.with_payload(|payload| payload.to_vec())
        })
    }

    pub(crate) fn ensure_owner_signing_key(&mut self) -> Result<&OwnerSigningKeyPair> {
        if self.owner_signing_key.is_none() {
            self.owner_signing_key = Some(OwnerSigningKeyPair::generate()?);
        }
        self.owner_signing_key.as_ref().ok_or_else(|| {
            Error::InvalidOperation("lockbox owner signing key is not available".to_string())
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
        let page_size = page_size_for_encoded_objects(&objects)?;
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
        self.rewrite_shared_compression_frames_before_removal(&entry)?;
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
                    for segment in &mut chunk.segments {
                        if segment.page_offset == old_offset
                            && kept_object_ids.contains(&segment.object_id)
                        {
                            segment.page_offset = new_offset;
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
                chunk.segments.iter().map(|segment| RecordRef {
                    offset: segment.page_offset,
                    len: segment.page_len,
                    object_id: segment.object_id,
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
                let Ok(header) = self.storage.read_at(offset, crate::page::PAGE_HEADER_LEN) else {
                    break;
                };
                let stored_body_len = u32::from_le_bytes(header[44..48].try_into().unwrap()) as u64;
                let stored_len = crate::page::PAGE_HEADER_LEN as u64 + stored_body_len;
                if offset + stored_len > len {
                    break;
                }
                let page_bytes = self.storage.read_at(offset, stored_len as usize)?;
                let page_size = physical_page_size_from_page_slice(&page_bytes)
                    .unwrap_or(DEFAULT_METADATA_PAGE_BYTES);
                if let Ok(commit_root) = self.read_commit_root_at(offset) {
                    if best.as_ref().is_none_or(
                        |(_, existing): &(u64, crate::commit_root::CommitRoot)| {
                            commit_root.sequence > existing.sequence
                        },
                    ) {
                        best = Some((offset, commit_root));
                    }
                    offset += page_size as u64;
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
        let key = Zeroizing::new(self.lockbox.key.with_bytes(|key| key.to_vec())?);
        Ok(crate::page::inspect_pages(
            &bytes,
            self.lockbox.lockbox_id,
            key.as_slice(),
        ))
    }

    /// Scan the current persisted storage and return a recovery report.
    pub fn recovery_report(&self) -> RecoveryReport {
        match self.lockbox.bytes() {
            Ok(bytes) => match self.lockbox.key.with_bytes(|key| key.to_vec()) {
                Ok(key) => RecoveryScanner::scan_bytes(bytes, Zeroizing::new(key).as_slice()),
                Err(_) => corrupt_recovery_report(),
            },
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
        variables_recovered: false,
        variable_count: 0,
        forms_recovered: false,
        form_definition_count: 0,
        form_record_count: 0,
    }
}

fn record_kind_from_object_kind(kind: PageObjectKind) -> Result<RecordKind> {
    match kind {
        PageObjectKind::PackedFileData | PageObjectKind::FileData => Ok(RecordKind::FilePage),
        PageObjectKind::Symlink => Ok(RecordKind::Symlink),
        PageObjectKind::VariableSet => Ok(RecordKind::Variable),
        PageObjectKind::VariableDelete => Ok(RecordKind::VariableDelete),
        PageObjectKind::Delete => Ok(RecordKind::Delete),
        PageObjectKind::TocLeaf | PageObjectKind::TocInternal => Ok(RecordKind::TocNode),
        PageObjectKind::CommitRoot => Ok(RecordKind::CommitRoot),
        PageObjectKind::CommitAuth => Ok(RecordKind::CommitAuth),
        PageObjectKind::FreeIndexLeaf | PageObjectKind::FreeIndexInternal => {
            Ok(RecordKind::FreeIndex)
        }
        PageObjectKind::KeyDirectory
        | PageObjectKind::VariableLeaf
        | PageObjectKind::VariableInternal
        | PageObjectKind::FormLeaf
        | PageObjectKind::FormInternal => Err(Error::CorruptRecord),
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
                .segments
                .iter()
                .map(|segment| (segment.page_offset, segment.page_len))
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
