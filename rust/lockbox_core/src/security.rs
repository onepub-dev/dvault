use unicode_normalization::UnicodeNormalization;

use crate::constants::{
    MAX_COMPONENT_BYTES, MAX_ENV_NAME_BYTES, MAX_ENV_VALUE_BYTES, MAX_PATH_BYTES, MAX_PATH_DEPTH,
};
use crate::{Error, Result};

pub(crate) fn validate_symlink(link_path: &str, target_path: &str) -> Result<()> {
    canonicalize_path(link_path, false)?;
    canonicalize_path(target_path, false)?;
    Ok(())
}

pub(crate) fn validate_path(path: &str) -> Result<()> {
    canonicalize_stored_path(path, false).map(|_| ())
}

pub(crate) fn canonicalize_path(path: &str, allow_dir: bool) -> Result<String> {
    let normalized = path.nfc().collect::<String>();
    validate_logical_path(&normalized, allow_dir)?;
    Ok(normalized)
}

pub(crate) fn canonicalize_stored_path(path: &str, allow_dir: bool) -> Result<String> {
    let normalized = path.nfc().collect::<String>();
    if normalized != path {
        return Err(Error::InvalidPath(path.to_string()));
    }
    validate_logical_path(path, allow_dir)?;
    Ok(normalized)
}

pub(crate) fn validate_permissions(permissions: u32) -> Result<u32> {
    if permissions <= 0o777 {
        Ok(permissions)
    } else {
        Err(Error::SecurityLimitExceeded(format!(
            "permissions {permissions:o} include unsupported bits"
        )))
    }
}

pub(crate) fn validate_glob(pattern: &str) -> Result<String> {
    if pattern.is_empty()
        || pattern.len() > MAX_PATH_BYTES
        || pattern.starts_with('/')
        || pattern.starts_with("//")
        || pattern.contains('\\')
        || pattern.contains('\0')
        || pattern.contains(':')
        || pattern.chars().any(is_forbidden_unicode)
    {
        return Err(Error::InvalidPath(pattern.to_string()));
    }
    for component in pattern.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(Error::InvalidPath(pattern.to_string()));
        }
    }
    Ok(pattern.nfc().collect::<String>())
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

fn validate_logical_path(path: &str, allow_dir: bool) -> Result<()> {
    let invalid = || Error::InvalidPath(path.to_string());
    let path = if allow_dir && path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    };

    if allow_dir && path == "/" {
        return Ok(());
    }

    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('\\')
        || path.contains('\0')
        || path.chars().any(is_forbidden_unicode)
        || path.contains(':')
    {
        return Err(invalid());
    }

    if !allow_dir && (path.len() == 1 || path.ends_with('/')) {
        return Err(invalid());
    }

    let mut depth = 0usize;
    for component in path.split('/').skip(1) {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > MAX_COMPONENT_BYTES
        {
            return Err(invalid());
        }
        depth += 1;
        if depth > MAX_PATH_DEPTH {
            return Err(invalid());
        }
    }
    Ok(())
}

fn is_forbidden_unicode(ch: char) -> bool {
    matches!(
        ch,
        '\u{0000}'..='\u{001f}'
            | '\u{007f}'..='\u{009f}'
            | '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{e0100}'..='\u{e01ef}'
    )
}

pub(crate) fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let text_parts: Vec<&str> = text.split('/').collect();
    glob_match_parts(&pattern_parts, &text_parts)
}

fn glob_match_parts(pattern: &[&str], text: &[&str]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern[0] == "**" {
        return glob_match_parts(&pattern[1..], text)
            || (!text.is_empty() && glob_match_parts(pattern, &text[1..]));
    }
    if text.is_empty() {
        return false;
    }
    glob_match_component(pattern[0], text[0]) && glob_match_parts(&pattern[1..], &text[1..])
}

fn glob_match_component(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let mut p = 0usize;
    let mut t = 0usize;
    let mut star = None;
    let mut star_text = 0usize;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            star_text = t;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            star_text += 1;
            t = star_text;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symlink_validation_requires_logical_paths() {
        assert!(validate_symlink("/links/current", "/docs/current").is_ok());

        for target in [
            "../outside",
            "/safe/../outside",
            "/C:/Users/target",
            "//server/share/target",
            "/safe\\target",
            "/safe/\0target",
        ] {
            assert!(
                matches!(
                    validate_symlink("/links/current", target),
                    Err(Error::InvalidPath(_))
                ),
                "target should be rejected: {target:?}"
            );
        }

        assert!(matches!(
            validate_symlink("/links/../current", "/docs/current"),
            Err(Error::InvalidPath(_))
        ));
    }
}
