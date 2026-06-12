#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
//! Native vault and unlock-cache support for reVault.
//!
//! This crate includes the **Lockbox Session Agent**, a local unlock-cache service
//! that reduces password prompts by keeping lockbox content keys in a short-lived,
//! in-memory process cache.
//!
//! The Lockbox Session Agent is started as a platform-specific local service
//! (Unix socket on Unix, named pipe on Windows), and is used automatically by
//! `lockbox` operations when a secret-dependent command needs a cached key.
//! Its cache uses secure frames for key-bearing traffic, supports TTL-based expiry,
//! supports explicit session management commands, and automatically clears cache
//! entries during suspend events.
//!
//! Key public entry points:
//! - `serve_agent` starts the session agent in-process.
//! - `get`, `put`, `forget`, `forget_all`, `list`, and `stop` operate the
//!   session cache.
//! - `begin_secret_activity` and `SecretActivityGuard` support suspend-protection
//!   and optional process termination behavior.
//! - `local_vault` manages the on-disk vault and metadata outside the agent cache.
//!
//! For the runtime behavior, command integration, and security settings, see the
//! project documentation in `docs/lockbox_session_agent.md`.

/// Secure string type re-exported from `lockbox_core`.
pub use lockbox_core::{SecretString, SecretVec};

mod active_secret;
mod agent_client;
mod agent_config;
mod agent_log;
mod agent_protocol;
mod content_key_store;
mod hex;
mod key_format;
mod noop_store;
mod platform_secret_store;
mod sleep_watcher;
mod vault;
mod vault_directory;

#[cfg(unix)]
mod unix;

#[cfg(windows)]
mod windows;

pub use agent_client::{
    begin_secret_activity, forget, forget_all, get, is_running, list, put, serve_agent, stop,
    verify_agent_transport_security, AgentClient, SecretActivityGuard,
};
pub use agent_log::{agent_log_destination, agent_log_path};
pub use agent_protocol::CachedLockbox;
pub use agent_protocol::SecretActivityKind;
pub(crate) use agent_protocol::{
    encode_control_err_response, encode_control_ok_response, encode_err_response, encode_forget,
    encode_forget_all, encode_get, encode_key_response, encode_list, encode_list_response,
    encode_miss_response, encode_ok_response, encode_put, encode_register_secret_activity,
    encode_registered_response, encode_stop, encode_unregister_secret_activity, frame_header_len,
    frame_message_type, frame_payload_len, is_control_message_type, max_message_bytes,
    parse_control_request, parse_control_response, parse_request, parse_response, AgentRequest,
    AgentResponse, ControlRequest, ControlResponse, DEFAULT_TTL_SECONDS,
};
pub use content_key_store::ContentKeyStore;
pub use hex::{decode_hex, encode_hex};
pub use key_format::{
    export_private_key, export_public_key, import_private_key, import_private_key_file,
    import_public_key, KeyFormat,
};
pub use noop_store::NoopStore;
pub use platform_secret_store::{
    auto_open_scope, disable_platform_secret_store, enable_platform_secret_store,
    forget_platform_vault_password, get_platform_vault_password, platform_secret_store_disabled,
    platform_secret_store_status, put_platform_vault_password, set_auto_open_scope, AutoOpenScope,
    PlatformSecretStoreStatus,
};
pub use vault::{local_vault, LocalVault, Vault};
pub use vault_directory::{
    backup_default_vault, default_vault_dir, default_vault_path, restore_default_vault,
    IdentityGeneration, IdentityGenerationStatus, IdentityHistory, KnownLockbox,
    StoredTrustedRecipient, VaultBackupManifest, VaultDirectory, CURRENT_VAULT_STRUCTURE_VERSION,
};
