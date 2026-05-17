#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
//! Core encrypted lockbox storage engine.
//!
//! `lockbox_core` owns the portable `.lbox` file format and the in-memory API
//! for storing files, symlinks, environment values, and key slots. It does not
//! know about a user's local vault or unlock-cache agent; those are implemented in
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

#[cfg(test)]
mod api_tests;
#[cfg(test)]
mod compression_regression_tests;

pub(crate) use file_format::{
    commit_root, header, key_directory, page, page_buffer, page_inspection, page_scanner, payload,
};
pub(crate) use keys::{crypto, key_derivation, key_slot, key_wrap, secret_vec};
pub(crate) use model::{
    entry, env_name, env_sensitivity, extract_policy, file_chunk, list_iter, list_options,
    lockbox_id, node_kind, page_object_packer, record, recovery_report, recovery_report_options,
};
pub(crate) use paths::{host_path, lockbox_path};
pub(crate) use storage::{cache_options, free_index, free_slot, memory_pressure, page_cache};
pub(crate) use toc::{env_btree, page_tree, toc_btree, toc_codec, toc_entry};

pub use cache_options::{CacheLimit, CacheStats, LockboxOptions, WorkloadProfile};
pub use entry::{LockboxEntry, LockboxEntryKind};
pub use env_name::EnvName;
pub use env_sensitivity::EnvSensitivity;
pub use error::{Error, Result};
pub use extract_policy::ExtractPolicy;
pub use key_slot::{LockboxKeySlot, LockboxKeySlotAlgorithm, LockboxKeySlotKind};
pub use key_wrap::{MlKemKeyPair, MlKemRecipientPublicKey, MlKemWrappedKey};
pub use list_iter::ListIter;
pub use list_options::ListOptions;
pub use lockbox::{
    EnvValueRef, Lockbox, LockboxCreate, LockboxInspector, LockboxUnlock, RecoveryScanner,
    UnlockedContentKey,
};
pub use lockbox_id::LockboxId;
pub use lockbox_path::LockboxPath;
pub use page_inspection::{PageInspection, PageObjectInspection};
pub use recovery_report::RecoveryReport;
pub use recovery_report_options::RecoveryReportOptions;
pub use secret_vec::{SecretString, SecretVec};
