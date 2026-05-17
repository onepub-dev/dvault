use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

use unicode_normalization::UnicodeNormalization;

use crate::constants::{MAX_COMPONENT_BYTES, MAX_PATH_BYTES, MAX_PATH_DEPTH};
use crate::{Error, Result};

/// Canonical path for an directory, file or symlink entry inside a lockbox.
///
/// `LockboxPath` is distinct from `std::path::Path`, which represents a host
/// filesystem path. Lockbox paths always use `/` separators, are stored in
/// canonical Unicode form, and are validated against the lockbox path rules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockboxPath(String);

impl LockboxPath {
    /// Validate and canonicalize a lockbox path.
    ///
    /// The root path `/` and trailing slash directory paths are allowed for
    /// APIs such as listing. File-specific APIs reject directory-only paths.
    ///
    /// Returns `Error::InvalidPath` if the path is relative, contains unsafe
    /// components, exceeds path limits, or contains unsupported characters.
    pub fn new(path: impl AsRef<str>) -> Result<Self> {
        Self::from_api(path.as_ref(), true)
    }

    /// Return the canonical string form of this lockbox path.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_api(path: &str, allow_dir: bool) -> Result<Self> {
        Ok(Self(canonicalize_api_path(path, allow_dir)?))
    }

    pub(crate) fn from_stored(path: &str, allow_dir: bool) -> Result<Self> {
        Ok(Self(canonicalize_stored_path(path, allow_dir)?))
    }

    pub(crate) fn as_file_path(&self) -> Result<&str> {
        validate_lockbox_path(&self.0, false)?;
        Ok(&self.0)
    }

    pub(crate) fn file_path(&self) -> Result<Self> {
        self.as_file_path()?;
        Ok(self.clone())
    }

    #[cfg(test)]
    pub(crate) fn from_unchecked_for_test(path: impl Into<String>) -> Self {
        Self(path.into())
    }
}

impl Borrow<str> for LockboxPath {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for LockboxPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LockboxPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for LockboxPath {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<&str> for LockboxPath {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<LockboxPath> for &str {
    fn eq(&self, other: &LockboxPath) -> bool {
        *self == other.0
    }
}

impl TryFrom<&str> for LockboxPath {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<String> for LockboxPath {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

pub(crate) fn canonicalize_api_path(path: &str, allow_dir: bool) -> Result<String> {
    if path.is_ascii() {
        validate_lockbox_path(path, allow_dir)?;
        return Ok(path.to_string());
    }
    let normalized = path.nfc().collect::<String>();
    validate_lockbox_path(&normalized, allow_dir)?;
    Ok(normalized)
}

pub(crate) fn canonicalize_stored_path(path: &str, allow_dir: bool) -> Result<String> {
    if path.is_ascii() {
        validate_lockbox_path(path, allow_dir)?;
        return Ok(path.to_string());
    }
    let normalized = path.nfc().collect::<String>();
    if normalized != path {
        return Err(Error::InvalidPath(path.to_string()));
    }
    validate_lockbox_path(path, allow_dir)?;
    Ok(normalized)
}

pub(crate) fn validate_stored_path(path: &str) -> Result<()> {
    LockboxPath::from_stored(path, false).map(|_| ())
}

pub(crate) fn validate_symlink_paths(link_path: &str, target_path: &str) -> Result<()> {
    LockboxPath::from_api(link_path, false)?;
    LockboxPath::from_api(target_path, false)?;
    Ok(())
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
    if pattern.is_ascii() {
        Ok(pattern.to_string())
    } else {
        Ok(pattern.nfc().collect::<String>())
    }
}

pub(crate) fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let text_parts: Vec<&str> = text.split('/').collect();
    glob_match_parts(&pattern_parts, &text_parts)
}

fn validate_lockbox_path(path: &str, allow_dir: bool) -> Result<()> {
    if path.is_ascii() {
        return validate_ascii_lockbox_path(path, allow_dir);
    }

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

fn validate_ascii_lockbox_path(path: &str, allow_dir: bool) -> Result<()> {
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
        || path
            .as_bytes()
            .iter()
            .any(|byte| matches!(*byte, 0x00..=0x1f | 0x7f | b'\\' | b':'))
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
    fn symlink_validation_requires_lockbox_paths() {
        assert!(validate_symlink_paths("/links/current", "/docs/current").is_ok());

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
                    validate_symlink_paths("/links/current", target),
                    Err(Error::InvalidPath(_))
                ),
                "target should be rejected: {target:?}"
            );
        }

        assert!(matches!(
            validate_symlink_paths("/links/../current", "/docs/current"),
            Err(Error::InvalidPath(_))
        ));
    }
}
