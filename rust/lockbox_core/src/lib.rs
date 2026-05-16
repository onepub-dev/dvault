#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
//! Core encrypted lockbox storage engine.
//!
//! `lockbox_core` owns the portable `.lbox` file format and the in-memory API
//! for storing files, symlinks, environment values, and key slots. It does not
//! know about a user's local vault or unlock-cache agent; those live in
//! `lockbox_vault`.

mod compression;
mod constants;
mod error;
mod fast_hash;
mod file_format;
mod index;
mod keys;
mod lockbox;
mod model;
mod paths;
mod scan;
mod security;
mod storage;
mod toc;

pub(crate) use file_format::{
    commit_root, header, key_directory, page, page_buffer, page_inspection, page_scanner, payload,
};
pub(crate) use keys::{crypto, key_derivation, key_slot, key_wrap, secret_vec};
pub(crate) use model::{
    entry, env_sensitivity, extract_policy, extracted_file, extracted_node, extracted_symlink,
    file_chunk, list_iter, list_options, lockbox_id, node_kind, page_object_packer, record,
    recovery_report, recovery_report_options,
};
pub(crate) use paths::{host_path, logical_path, symlink};
pub(crate) use storage::{cache_options, free_index, free_slot, memory_pressure, page_cache};
pub(crate) use toc::{env_btree, manifest_codec, manifest_entry, page_tree, toc_btree};

pub use cache_options::{CacheLimit, CacheStats, LockboxOptions, WorkloadProfile};
pub use entry::{Entry, EntryKind};
pub use env_sensitivity::EnvSensitivity;
pub use error::{Error, Result};
pub use extract_policy::ExtractPolicy;
pub use extracted_file::ExtractedFile;
pub use extracted_node::ExtractedNode;
pub use extracted_symlink::ExtractedSymlink;
pub use key_derivation::derive_key_from_password;
pub use key_slot::{KeySlotInfo, KeySlotKind};
pub use key_wrap::{MlKemKeyPair, MlKemRecipientKey, MlKemWrappedKey};
pub use list_iter::ListIter;
pub use list_options::ListOptions;
pub use lockbox::{Lockbox, LockboxCreate, LockboxUnlock, UnlockedContentKey};
pub use lockbox_id::LockboxId;
pub use page_inspection::{PageInspection, PageObjectInspection};
pub use recovery_report::RecoveryReport;
pub use recovery_report_options::RecoveryReportOptions;
pub use secret_vec::{
    secure_allocation_chunk_bytes, secure_memory_capabilities, secure_read_access,
    set_secure_allocation_chunk_bytes, set_weakened_allocation_allowed,
    weakened_allocation_allowed, AllocationSecurity, SecretString, SecretVec,
    SecureMemoryCapabilities, SecureReadAccess,
};
