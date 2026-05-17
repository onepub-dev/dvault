use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

use crate::security::validate_env_name;
use crate::{Error, Result};

/// Validated environment variable name stored inside a lockbox.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvName(String);

impl EnvName {
    /// Validate and canonicalize an environment variable name.
    ///
    /// Returns `Error::InvalidPath` if the name is empty, too long, starts
    /// with an invalid character, or contains characters outside `[A-Za-z0-9_]`.
    pub fn new(name: impl AsRef<str>) -> Result<Self> {
        Ok(Self(validate_env_name(name.as_ref())?))
    }

    /// Return the validated environment variable name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for EnvName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for EnvName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for EnvName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&str> for EnvName {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<String> for EnvName {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}
