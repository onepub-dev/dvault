#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
//! Native vault and unlock-cache support for Lockbox.
//!
//! This crate layers local workstation/server conveniences on top of
//! `lockbox_core`: an agent-backed content-key cache, a password-protected
//! local vault file, and helpers for importing and exporting recipient keys.
//! It is intended for native applications. Browser and other sandboxed
//! environments should usually use `lockbox_core` directly.

/// Secure string type re-exported from `lockbox_core`.
pub use lockbox_core::{SecretString, SecretVec};

mod agent_client;
mod agent_protocol;
mod content_key_store;
mod hex;
mod key_format;
mod noop_store;
mod vault;
mod vault_directory;

#[cfg(unix)]
mod unix;

#[cfg(windows)]
mod windows;

pub use agent_client::{
    forget, forget_all, get, put, serve_agent, verify_agent_transport_security, AgentClient,
};
#[cfg(unix)]
pub(crate) use agent_protocol::max_request_bytes;
pub(crate) use agent_protocol::{
    encode_forget, encode_forget_all, encode_get, encode_put, parse_request, AgentRequest,
    DEFAULT_TTL_SECONDS,
};
pub use content_key_store::ContentKeyStore;
pub use hex::{decode_hex, encode_hex};
pub use key_format::{
    export_private_key, export_public_key, import_private_key, import_private_key_file,
    import_public_key, KeyFormat,
};
pub use noop_store::NoopStore;
pub use vault::{local_vault, LocalVault, Vault};
pub use vault_directory::{
    default_vault_dir, default_vault_path, StoredTrustedRecipient, VaultDirectory,
};
