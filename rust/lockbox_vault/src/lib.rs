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
mod platform_secret_store;
mod vault;
mod vault_directory;

#[cfg(unix)]
mod unix;

#[cfg(windows)]
mod windows;

pub use agent_client::{
    forget, forget_all, get, is_running, list, put, serve_agent, stop,
    verify_agent_transport_security, AgentClient,
};
#[cfg(unix)]
pub(crate) use agent_protocol::max_message_bytes;
#[cfg(windows)]
pub(crate) use agent_protocol::max_message_bytes;
pub use agent_protocol::CachedLockbox;
pub(crate) use agent_protocol::{
    encode_forget, encode_forget_all, encode_get, encode_key_response, encode_list,
    encode_list_response, encode_put, encode_response_line, encode_stop, parse_request,
    parse_response, AgentRequest, AgentResponse, DEFAULT_TTL_SECONDS,
};
pub use content_key_store::ContentKeyStore;
pub use hex::{decode_hex, encode_hex};
pub use key_format::{
    export_private_key, export_public_key, import_private_key, import_private_key_file,
    import_public_key, KeyFormat,
};
pub use noop_store::NoopStore;
pub use platform_secret_store::{
    disable_platform_secret_store, enable_platform_secret_store, forget_platform_vault_password,
    get_platform_vault_password, platform_secret_store_disabled, platform_secret_store_status,
    put_platform_vault_password, PlatformSecretStoreStatus,
};
pub use vault::{local_vault, LocalVault, Vault};
pub use vault_directory::{
    default_vault_dir, default_vault_path, IdentityGeneration, IdentityGenerationStatus,
    IdentityHistory, KnownLockbox, StoredTrustedRecipient, VaultDirectory,
    CURRENT_VAULT_STRUCTURE_VERSION,
};
