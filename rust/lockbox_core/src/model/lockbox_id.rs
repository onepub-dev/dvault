use std::fmt;

use crate::{Error, Result};

/// Stable UUID-style identifier embedded in each lockbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockboxId([u8; 16]);

impl LockboxId {
    /// Generate a new random version-4 UUID style lockbox id.
    pub fn new_random() -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|err| Error::Io(err.to_string()))?;
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Ok(Self(bytes))
    }

    /// Construct a lockbox id from raw bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the raw 16-byte id.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for LockboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}
