use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

use crate::security::validate_variable_name;
use crate::{Error, Result};

/// Validated variable name stored inside a lockbox.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VariableName(String);

impl VariableName {
    /// Validate and canonicalize a variable name.
    ///
    /// Plain names such as `API_KEY` are canonicalized to `/API_KEY`. Absolute
    /// names such as `/production/API_KEY` are treated as grouped variable labels.
    ///
    /// Returns `Error::InvalidPath` if the name is empty, too long, has unsafe
    /// path structure, or contains components outside `[A-Za-z0-9_]`.
    pub fn new(name: impl AsRef<str>) -> Result<Self> {
        Ok(Self(validate_variable_name(name.as_ref())?))
    }

    /// Return the validated variable name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return true when this name matches a validated variable-name pattern.
    pub fn matches_pattern(&self, pattern: &VariableNamePattern) -> bool {
        pattern.matches(self)
    }
}

/// Validated variable-name filter.
///
/// Plain names such as `API_KEY` match only that root-level variable. Absolute
/// paths such as `/production` match that path and its children. Glob patterns
/// such as `/production/**` or `**/API_KEY` match canonical variable paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableNamePattern {
    mode: VariableNamePatternMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VariableNamePatternMode {
    Exact(String),
    Prefix(String),
    Glob(String),
}

impl VariableNamePattern {
    /// Validate and canonicalize a variable-name filter.
    pub fn new(pattern: impl AsRef<str>) -> Result<Self> {
        let pattern = pattern.as_ref();
        if contains_glob(pattern) {
            return Ok(Self {
                mode: VariableNamePatternMode::Glob(validate_variable_glob(pattern)?),
            });
        }
        let name = VariableName::new(pattern)?;
        let mode = if pattern.starts_with('/') {
            VariableNamePatternMode::Prefix(name.as_str().to_string())
        } else {
            VariableNamePatternMode::Exact(name.as_str().to_string())
        };
        Ok(Self { mode })
    }

    /// Return true when the supplied variable name matches this pattern.
    pub fn matches(&self, name: &VariableName) -> bool {
        match &self.mode {
            VariableNamePatternMode::Exact(pattern) => name.as_str() == pattern,
            VariableNamePatternMode::Prefix(pattern) => {
                name.as_str() == pattern
                    || name
                        .as_str()
                        .strip_prefix(pattern)
                        .is_some_and(|rest| rest.starts_with('/'))
            }
            VariableNamePatternMode::Glob(pattern) => {
                let name = name.as_str().strip_prefix('/').unwrap_or(name.as_str());
                glob_matches(pattern, name)
            }
        }
    }
}

impl AsRef<str> for VariableName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for VariableName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VariableName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for VariableName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&str> for VariableName {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<String> for VariableName {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

fn contains_glob(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

fn validate_variable_glob(pattern: &str) -> Result<String> {
    if pattern.is_empty()
        || pattern == "/"
        || pattern.ends_with('/')
        || pattern.starts_with("//")
        || pattern.contains('\\')
        || pattern.contains('\0')
        || pattern.contains(':')
    {
        return Err(Error::InvalidPath(pattern.to_string()));
    }
    let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
    for component in pattern.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(Error::InvalidPath(pattern.to_string()));
        }
        if component == "**" {
            continue;
        }
        if !component
            .chars()
            .all(|ch| ch == '_' || ch == '*' || ch == '?' || ch.is_ascii_alphanumeric())
        {
            return Err(Error::InvalidPath(pattern.to_string()));
        }
    }
    Ok(pattern.to_string())
}

fn glob_matches(pattern: &str, text: &str) -> bool {
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
