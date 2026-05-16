use std::{env, ffi::OsString, fmt, str};

use zeroize::Zeroize;

use crate::{
    error::{Error, Result},
    secure_access::{read_access, SecureReadAccess},
    secure_vec::SecureVec,
};

pub struct SecureString {
    bytes: SecureVec,
}

impl SecureString {
    pub fn new() -> Self {
        Self {
            bytes: SecureVec::new(),
        }
    }

    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self {
            bytes: SecureVec::try_from_vec(bytes)?,
        })
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            bytes: SecureVec::try_from_slice(bytes)?,
        })
    }

    pub fn from_secure_vec(bytes: SecureVec) -> Self {
        Self { bytes }
    }

    pub fn try_from_utf8(bytes: Vec<u8>) -> Result<Self> {
        str::from_utf8(&bytes).map_err(|_| Error::InvalidUtf8)?;
        Self::try_from_bytes(bytes)
    }

    pub fn try_from_env(name: &str) -> Result<Option<Self>> {
        env::var_os(name).map(os_string_to_secure).transpose()
    }

    pub fn try_from_os_string(value: OsString) -> Result<Self> {
        os_string_to_secure(value)
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            bytes: self.bytes.try_clone()?,
        })
    }

    pub fn with_str<R>(&self, f: impl FnOnce(&str) -> R) -> Result<R> {
        read_access(|access| self.with_str_in(access, f))
    }

    pub fn with_str_in<R>(
        &self,
        access: &SecureReadAccess<'_>,
        f: impl FnOnce(&str) -> R,
    ) -> Result<R> {
        self.bytes.with_bytes_in(access, |bytes| {
            let text = str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
            Ok(f(text))
        })?
    }

    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        self.bytes.with_bytes(f)
    }

    pub fn with_bytes_in<R>(
        &self,
        access: &SecureReadAccess<'_>,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R> {
        self.bytes.with_bytes_in(access, f)
    }

    pub fn append_to_secure_vec(&self, target: &mut SecureVec) -> Result<()> {
        target.try_extend_from_secure(&self.bytes)
    }

    pub fn try_push_byte(&mut self, byte: u8) -> Result<()> {
        self.bytes.try_push(byte)
    }

    pub fn try_extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        self.bytes.try_extend_from_slice(bytes)
    }

    pub fn try_push_utf8_char(&mut self, ch: char) -> Result<()> {
        let mut encoded = [0u8; 4];
        let text = ch.encode_utf8(&mut encoded);
        let result = self.bytes.try_extend_from_slice(text.as_bytes());
        encoded.zeroize();
        result
    }

    pub fn try_pop_byte(&mut self) -> Result<Option<u8>> {
        self.bytes.try_pop()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn zeroize(&mut self) -> Result<()> {
        self.bytes.zeroize()
    }
}

impl Default for SecureString {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureString")
            .field("len", &self.bytes.len())
            .field("redacted", &true)
            .finish()
    }
}

impl PartialEq for SecureString {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for SecureString {}

#[cfg(unix)]
fn os_string_to_secure(value: OsString) -> Result<SecureString> {
    use std::os::unix::ffi::OsStringExt;

    SecureString::try_from_bytes(value.into_vec())
}

#[cfg(windows)]
fn os_string_to_secure(value: OsString) -> Result<SecureString> {
    use std::os::windows::ffi::OsStrExt;

    let mut secret = SecureString::new();
    for decoded in char::decode_utf16(value.encode_wide()) {
        if let Ok(ch) = decoded {
            secret.try_push_utf8_char(ch)?;
        }
    }
    Ok(secret)
}

#[cfg(not(any(unix, windows)))]
fn os_string_to_secure(value: OsString) -> Result<SecureString> {
    let mut secret = SecureString::new();
    for ch in value.to_string_lossy().chars() {
        secret.try_push_utf8_char(ch)?;
    }
    Ok(secret)
}
