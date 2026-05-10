use crate::{Error, Result};
use std::{fmt, str};
use zeroize::Zeroize;

pub struct SecretBytes {
    bytes: Vec<u8>,
    locked: bool,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        let locked = lock_memory(&bytes);
        Self { bytes, locked }
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn clone_exposed(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

#[derive(Clone)]
pub struct SecretString {
    bytes: SecretBytes,
}

impl SecretString {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes: SecretBytes::new(bytes),
        }
    }

    pub fn expose_bytes(&self) -> &[u8] {
        self.bytes.expose()
    }

    pub fn expose_str(&self) -> Result<&str> {
        str::from_utf8(self.expose_bytes()).map_err(|_| Error::InvalidKey)
    }

    pub fn clone_exposed_bytes(&self) -> Vec<u8> {
        self.bytes.clone_exposed()
    }

    pub fn zeroize(&mut self) {
        self.bytes.bytes.zeroize();
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretString")
            .field("len", &self.bytes.expose().len())
            .field("redacted", &true)
            .finish()
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.bytes.clone())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.bytes.len())
            .field("redacted", &true)
            .finish()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
        if self.locked {
            unlock_memory(&self.bytes);
        }
    }
}

#[cfg(unix)]
fn lock_memory(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    unsafe { libc::mlock(bytes.as_ptr().cast(), bytes.len()) == 0 }
}

#[cfg(unix)]
fn unlock_memory(bytes: &[u8]) {
    if !bytes.is_empty() {
        unsafe {
            libc::munlock(bytes.as_ptr().cast(), bytes.len());
        }
    }
}

#[cfg(windows)]
fn lock_memory(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    unsafe {
        windows_sys::Win32::System::Memory::VirtualLock(bytes.as_ptr().cast(), bytes.len()) != 0
    }
}

#[cfg(windows)]
fn unlock_memory(bytes: &[u8]) {
    if !bytes.is_empty() {
        unsafe {
            windows_sys::Win32::System::Memory::VirtualUnlock(bytes.as_ptr().cast(), bytes.len());
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn lock_memory(_bytes: &[u8]) -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
fn unlock_memory(_bytes: &[u8]) {}
