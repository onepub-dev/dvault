use crate::constants::{MAX_ENV_NAME_BYTES, MAX_ENV_VALUE_BYTES};
use crate::{Error, Result};

pub(crate) fn validate_permissions(permissions: u32) -> Result<u32> {
    if permissions <= 0o777 {
        Ok(permissions)
    } else {
        Err(Error::SecurityLimitExceeded(format!(
            "permissions {permissions:o} include unsupported bits"
        )))
    }
}

pub(crate) fn validate_env_name(name: &str) -> Result<String> {
    if name.is_empty()
        || name.len() > MAX_ENV_NAME_BYTES
        || !name
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        || !name
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return Err(Error::InvalidPath(name.to_string()));
    }
    Ok(name.to_string())
}

pub(crate) fn validate_env_value(value: &str) -> Result<String> {
    if value.len() > MAX_ENV_VALUE_BYTES
        || value.contains('\0')
        || value.chars().any(|ch| {
            matches!(ch, '\u{0001}'..='\u{0008}' | '\u{000b}' | '\u{000c}' | '\u{000e}'..='\u{001f}' | '\u{007f}'..='\u{009f}')
        })
    {
        return Err(Error::SecurityLimitExceeded(
            "environment variable value is invalid or too large".to_string(),
        ));
    }
    Ok(value.to_string())
}
