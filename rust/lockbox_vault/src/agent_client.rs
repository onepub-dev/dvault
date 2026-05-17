use lockbox_core::{Error, LockboxId, Result};
use std::io;

use crate::ContentKeyStore;

#[cfg(unix)]
use crate::unix as platform;

#[cfg(windows)]
use crate::windows as platform;

#[cfg(not(any(unix, windows)))]
mod platform {
    use lockbox_core::LockboxId;
    use std::io;

    pub(crate) fn serve_agent() -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "lockbox agent is not supported on this platform",
        ))
    }

    pub(crate) fn verify_agent_transport_security() -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn get(_lockbox_id: LockboxId) -> io::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    pub(crate) fn put(_lockbox_id: LockboxId, _key: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "lockbox agent is not supported on this platform",
        ))
    }

    pub(crate) fn forget(_lockbox_id: LockboxId) -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn forget_all() -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AgentClient;

impl ContentKeyStore for AgentClient {
    fn get_content_key(&self, lockbox_id: LockboxId) -> Result<Option<Vec<u8>>> {
        get(lockbox_id).map_err(io_to_core)
    }

    fn put_content_key(&self, lockbox_id: LockboxId, key: &[u8]) -> Result<()> {
        put(lockbox_id, key).map_err(io_to_core)
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

pub fn serve_agent() -> io::Result<()> {
    platform::serve_agent()
}

pub fn verify_agent_transport_security() -> io::Result<()> {
    platform::verify_agent_transport_security()
}

pub fn get(lockbox_id: LockboxId) -> io::Result<Option<Vec<u8>>> {
    platform::get(lockbox_id)
}

pub fn put(lockbox_id: LockboxId, key: &[u8]) -> io::Result<()> {
    platform::put(lockbox_id, key)
}

pub fn forget(lockbox_id: LockboxId) -> io::Result<()> {
    platform::forget(lockbox_id)
}

pub fn forget_all() -> io::Result<()> {
    platform::forget_all()
}
