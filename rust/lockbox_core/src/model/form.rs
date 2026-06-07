use std::sync::Arc;

use crate::{Error, LockboxPath, Result, SecretString};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FormTypeId(String);

impl FormTypeId {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        if value.len() != 36 || !value.chars().all(|ch| ch == '-' || ch.is_ascii_hexdigit()) {
            return Err(Error::InvalidInput(format!(
                "invalid form type id: {value}"
            )));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub(crate) fn new_random() -> Result<Self> {
        Ok(Self(crate::LockboxId::new_random()?.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FormTypeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormDefinition {
    pub type_id: FormTypeId,
    pub alias: String,
    pub revision: u32,
    pub name: String,
    pub fields: Vec<FormFieldDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormFieldDefinition {
    pub id: String,
    pub label: String,
    pub kind: FormFieldKind,
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormFieldKind {
    Text,
    Secret,
    Url,
    Email,
    Date,
    Month,
    Notes,
    Number,
    Otp,
}

impl FormFieldKind {
    pub fn is_secret(self) -> bool {
        matches!(self, Self::Secret | Self::Otp)
    }

    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Text => 1,
            Self::Secret => 2,
            Self::Url => 3,
            Self::Email => 4,
            Self::Date => 5,
            Self::Month => 6,
            Self::Notes => 7,
            Self::Number => 8,
            Self::Otp => 9,
        }
    }

    pub(crate) fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Text),
            2 => Ok(Self::Secret),
            3 => Ok(Self::Url),
            4 => Ok(Self::Email),
            5 => Ok(Self::Date),
            6 => Ok(Self::Month),
            7 => Ok(Self::Notes),
            8 => Ok(Self::Number),
            9 => Ok(Self::Otp),
            _ => Err(Error::CorruptRecord),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FormRecord {
    pub path: LockboxPath,
    pub name: String,
    pub type_id: FormTypeId,
    pub definition_alias: String,
    pub definition_revision: u32,
    pub values: Vec<FormFieldValue>,
}

#[derive(Debug, Clone)]
pub struct FormFieldValue {
    pub field_id: String,
    pub captured_label: String,
    pub kind: FormFieldKind,
    pub value: FormValue,
}

#[derive(Debug, Clone)]
pub enum FormValue {
    Normal(String),
    Secret(Arc<SecretString>),
}

impl FormValue {
    pub fn normal(value: impl Into<String>) -> Self {
        Self::Normal(value.into())
    }

    pub fn secret(value: SecretString) -> Self {
        Self::Secret(Arc::new(value))
    }

    pub fn is_secret(&self) -> bool {
        matches!(self, Self::Secret(_))
    }
}

pub(crate) fn validate_form_alias(value: &str) -> Result<String> {
    validate_identifier(value, "form alias")
}

pub(crate) fn validate_form_field_id(value: &str) -> Result<String> {
    validate_identifier(value, "form field id")
}

pub(crate) fn validate_form_label(value: &str, description: &str) -> Result<String> {
    validate_text(value, description)?;
    Ok(value.to_string())
}

pub(crate) fn validate_form_record_name(value: &str) -> Result<String> {
    validate_text(value, "form record name")?;
    if value.trim().is_empty() {
        return Err(Error::InvalidInput(
            "form record name cannot be empty".to_string(),
        ));
    }
    Ok(value.to_string())
}

pub(crate) fn validate_form_value(kind: FormFieldKind, value: &FormValue) -> Result<()> {
    if kind.is_secret() != value.is_secret() {
        return Err(Error::InvalidOperation(
            "form field value sensitivity does not match the field definition".to_string(),
        ));
    }
    match value {
        FormValue::Normal(value) => validate_kind_text(kind, value),
        FormValue::Secret(value) => value.with_str(|value| validate_kind_text(kind, value))?,
    }
}

fn validate_identifier(value: &str, description: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        || !value
            .chars()
            .all(|ch| ch == '_' || ch == '-' || ch.is_ascii_alphanumeric())
    {
        return Err(Error::InvalidInput(format!(
            "invalid {description}: {value}"
        )));
    }
    Ok(value.to_string())
}

fn validate_text(value: &str, description: &str) -> Result<()> {
    if value.len() > crate::constants::MAX_ENV_VALUE_BYTES {
        return Err(Error::SecurityLimitExceeded(format!(
            "{description} exceeds {} bytes",
            crate::constants::MAX_ENV_VALUE_BYTES
        )));
    }
    if value.contains('\0')
        || value.chars().any(|ch| {
            matches!(ch, '\u{0001}'..='\u{0008}' | '\u{000b}' | '\u{000c}' | '\u{000e}'..='\u{001f}' | '\u{007f}'..='\u{009f}')
        })
    {
        return Err(Error::InvalidInput(format!(
            "{description} contains unsupported control characters"
        )));
    }
    Ok(())
}

fn validate_kind_text(kind: FormFieldKind, value: &str) -> Result<()> {
    validate_text(value, "form field value")?;
    match kind {
        FormFieldKind::Url if !value.is_empty() => {
            if !(value.starts_with("https://") || value.starts_with("http://")) {
                return Err(Error::InvalidInput(
                    "url form field values must start with http:// or https://".to_string(),
                ));
            }
        }
        FormFieldKind::Email if !value.is_empty() => {
            if value.contains(char::is_whitespace)
                || !value.contains('@')
                || value.starts_with('@')
                || value.ends_with('@')
            {
                return Err(Error::InvalidInput(
                    "email form field value is not a valid email address".to_string(),
                ));
            }
        }
        FormFieldKind::Date if !value.is_empty() => validate_fixed_date(value, false)?,
        FormFieldKind::Month if !value.is_empty() => validate_fixed_date(value, true)?,
        FormFieldKind::Number if !value.is_empty() => {
            value.parse::<f64>().map_err(|_| {
                Error::InvalidInput("number form field value is not numeric".to_string())
            })?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_fixed_date(value: &str, month_only: bool) -> Result<()> {
    let expected_len = if month_only { 7 } else { 10 };
    if value.len() != expected_len {
        return Err(Error::InvalidInput(
            "date form field value must use YYYY-MM or YYYY-MM-DD".to_string(),
        ));
    }
    let bytes = value.as_bytes();
    if bytes[4] != b'-'
        || (!month_only && bytes[7] != b'-')
        || !bytes
            .iter()
            .enumerate()
            .all(|(idx, byte)| matches!(idx, 4 | 7) || byte.is_ascii_digit())
    {
        return Err(Error::InvalidInput(
            "date form field value must use YYYY-MM or YYYY-MM-DD".to_string(),
        ));
    }
    let month = value[5..7]
        .parse::<u8>()
        .map_err(|_| Error::InvalidInput("date form field value month is invalid".to_string()))?;
    if !(1..=12).contains(&month) {
        return Err(Error::InvalidInput(
            "date form field value month is invalid".to_string(),
        ));
    }
    if !month_only {
        let day = value[8..10]
            .parse::<u8>()
            .map_err(|_| Error::InvalidInput("date form field value day is invalid".to_string()))?;
        if !(1..=31).contains(&day) {
            return Err(Error::InvalidInput(
                "date form field value day is invalid".to_string(),
            ));
        }
    }
    Ok(())
}
