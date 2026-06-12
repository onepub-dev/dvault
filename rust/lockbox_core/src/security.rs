use crate::constants::{MAX_VARIABLE_NAME_BYTES, MAX_VARIABLE_VALUE_BYTES};
use crate::{Error, Result};

pub(crate) fn validate_permissions(permissions: u32) -> Result<u32> {
    if permissions <= 0o777 {
        Ok(permissions)
    } else {
        Err(Error::InvalidInput(format!(
            "permissions {permissions:o} include unsupported bits"
        )))
    }
}

pub(crate) fn validate_variable_name(name: &str) -> Result<String> {
    if name.is_empty() || name.len() > MAX_VARIABLE_NAME_BYTES {
        return Err(Error::InvalidPath(name.to_string()));
    }
    let canonical = if name.starts_with('/') {
        validate_variable_path(name)?;
        name.to_string()
    } else {
        validate_variable_component(name, name)?;
        format!("/{name}")
    };
    if canonical.len() > MAX_VARIABLE_NAME_BYTES {
        return Err(Error::InvalidPath(name.to_string()));
    }
    Ok(canonical)
}

fn validate_variable_path(path: &str) -> Result<()> {
    if path.len() == 1
        || path.ends_with('/')
        || path.starts_with("//")
        || path.contains('\\')
        || path.contains('\0')
        || path.contains(':')
    {
        return Err(Error::InvalidPath(path.to_string()));
    }
    for component in path.split('/').skip(1) {
        validate_variable_component(component, path)?;
    }
    Ok(())
}

fn validate_variable_component(component: &str, original: &str) -> Result<()> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || !component
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        || !component
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return Err(Error::InvalidPath(original.to_string()));
    }
    Ok(())
}

pub(crate) fn validate_variable_value(value: &str) -> Result<String> {
    validate_variable_value_ref(value)?;
    Ok(value.to_string())
}

pub(crate) fn validate_variable_value_ref(value: &str) -> Result<()> {
    if value.len() > MAX_VARIABLE_VALUE_BYTES {
        return Err(Error::SecurityLimitExceeded(format!(
            "variable value exceeds {MAX_VARIABLE_VALUE_BYTES} bytes"
        )));
    }
    if value.contains('\0')
        || value.chars().any(|ch| {
            matches!(ch, '\u{0001}'..='\u{0008}' | '\u{000b}' | '\u{000c}' | '\u{000e}'..='\u{001f}' | '\u{007f}'..='\u{009f}')
        })
    {
        return Err(Error::InvalidInput(
            "variable value contains unsupported control characters".to_string(),
        ));
    }
    Ok(())
}
