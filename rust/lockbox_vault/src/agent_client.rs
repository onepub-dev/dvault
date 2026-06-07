use lockbox_core::{Error, LockboxId, Result, SecretVec};
use std::io;
use std::path::Path;

use crate::{CachedLockbox, ContentKeyStore, SecretActivityKind};

#[cfg(unix)]
use crate::unix as platform;

#[cfg(windows)]
use crate::windows as platform;

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::{CachedLockbox, SecretActivityKind, SecretVec};
    use lockbox_core::LockboxId;
    use std::io;

    pub(crate) fn serve_agent() -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "lockbox session agent is not supported on this platform",
        ))
    }

    pub(crate) fn verify_agent_transport_security() -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn get(_lockbox_id: LockboxId) -> io::Result<Option<SecretVec>> {
        Ok(None)
    }

    pub(crate) fn put(
        _lockbox_id: LockboxId,
        _key: &SecretVec,
        _path: Option<&str>,
        _ttl_seconds: Option<u64>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "lockbox session agent is not supported on this platform",
        ))
    }

    pub(crate) fn forget(_lockbox_id: LockboxId) -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn forget_all() -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn stop() -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn list() -> io::Result<Vec<CachedLockbox>> {
        Ok(Vec::new())
    }

    pub(crate) fn is_running() -> bool {
        false
    }

    pub(crate) fn register_secret_activity(_kind: SecretActivityKind) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "lockbox session agent is not supported on this platform",
        ))
    }

    pub(crate) fn unregister_secret_activity(_pid: u32, _token: u64) -> io::Result<()> {
        Ok(())
    }
}

/// Content-key store backed by the platform session agent.
///
/// On Unix this uses the crate's Unix-domain-socket transport. On Windows it
/// uses the named-pipe transport. Unsupported platforms expose a client that
/// cannot store keys and returns cache misses for lookups.
#[derive(Debug, Clone, Copy, Default)]
pub struct AgentClient;

impl ContentKeyStore for AgentClient {
    fn get_content_key(&self, lockbox_id: LockboxId) -> Result<Option<SecretVec>> {
        get(lockbox_id).map_err(io_to_core)
    }

    fn put_content_key(&self, lockbox_id: LockboxId, key: SecretVec) -> Result<()> {
        platform::put(lockbox_id, &key, None, None).map_err(io_to_core)
    }

    fn put_content_key_for_path(
        &self,
        lockbox_id: LockboxId,
        key: SecretVec,
        path: &Path,
    ) -> Result<()> {
        platform::put(lockbox_id, &key, Some(&path.display().to_string()), None).map_err(io_to_core)
    }

    fn put_content_key_for_path_with_ttl(
        &self,
        lockbox_id: LockboxId,
        key: SecretVec,
        path: &Path,
        ttl_seconds: u64,
    ) -> Result<()> {
        platform::put(
            lockbox_id,
            &key,
            Some(&path.display().to_string()),
            Some(ttl_seconds),
        )
        .map_err(io_to_core)
    }

    fn forget_content_key(&self, lockbox_id: LockboxId) -> Result<()> {
        forget(lockbox_id).map_err(io_to_core)
    }

    fn forget_all_content_keys(&self) -> Result<()> {
        forget_all().map_err(io_to_core)
    }
}

fn io_to_core(err: io::Error) -> Error {
    Error::Io(err.to_string())
}

/// Runs the platform content-key agent in the current process.
///
/// The function blocks while serving requests and returns when the platform
/// transport exits or fails.
pub fn serve_agent() -> io::Result<()> {
    platform::serve_agent()
}

/// Verifies that the current platform agent transport is configured securely.
///
/// This checks platform-specific transport requirements, such as local-only
/// access and owner restrictions where those concepts exist.
pub fn verify_agent_transport_security() -> io::Result<()> {
    platform::verify_agent_transport_security()
}

/// Reads a cached content key from the platform agent.
pub fn get(lockbox_id: LockboxId) -> io::Result<Option<SecretVec>> {
    platform::get(lockbox_id)
}

/// Stores a content key in the platform agent.
pub fn put(lockbox_id: LockboxId, key: &[u8]) -> io::Result<()> {
    let key = SecretVec::try_from_slice(key).map_err(io::Error::other)?;
    platform::put(lockbox_id, &key, None, None)
}

/// Removes one content key from the platform agent.
pub fn forget(lockbox_id: LockboxId) -> io::Result<()> {
    platform::forget(lockbox_id)
}

/// Removes all content keys from the platform agent.
pub fn forget_all() -> io::Result<()> {
    platform::forget_all()
}

/// Stops the platform agent after clearing all cached content keys.
pub fn stop() -> io::Result<()> {
    platform::stop()
}

/// Lists cached lockboxes known to the platform agent.
pub fn list() -> io::Result<Vec<CachedLockbox>> {
    platform::list()
}

/// Returns true when the platform agent transport is currently reachable.
pub fn is_running() -> bool {
    platform::is_running()
}

/// Registration guard for a command that may hold decrypted secrets in memory.
pub struct SecretActivityGuard {
    pid: u32,
    token: Option<u64>,
}

impl Drop for SecretActivityGuard {
    fn drop(&mut self) {
        let Some(token) = self.token.take() else {
            return;
        };
        let _ = platform::unregister_secret_activity(self.pid, token);
    }
}

/// Registers the current process as running a high-level secret activity.
///
/// While registered, the agent may hold a system sleep inhibitor and will
/// terminate the process if a suspend request still arrives.
pub fn begin_secret_activity(kind: SecretActivityKind) -> io::Result<SecretActivityGuard> {
    let pid = std::process::id();
    let token = platform::register_secret_activity(kind).ok();
    Ok(SecretActivityGuard { pid, token })
}
