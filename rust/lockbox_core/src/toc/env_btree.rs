use std::collections::BTreeMap;
use std::sync::Arc;

use crate::constants::DEFAULT_METADATA_MAX_PAGE_BODY_BYTES;
use crate::page_tree::{
    decode_page_tree_children, encode_page_tree_children, group_by_encoded_size,
    page_tree_child_encoded_len, PageTreeChild,
};
use crate::secret_vec::{secure_read_access, SecureVec};
use crate::security::{validate_env_name, validate_env_value_ref};
use crate::{EnvName, EnvSensitivity, Error, Result, SecretString};

const ENV_NODE_VERSION: u8 = 1;
const ENV_NODE_VERSION_WITH_SENSITIVITY: u8 = 2;
const ENV_LEAF: u8 = 1;
const ENV_INTERNAL: u8 = 2;
const ENV_NODE_PREFIX_BYTES: usize = 2;
const ENTRY_COUNT_BYTES: usize = 4;
const CHILD_COUNT_BYTES: usize = 4;
const ENV_PLAIN_PREFIX: &str = ".plain/";
const ENV_SECRET_PREFIX: &str = ".secret/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvEntry {
    pub(crate) name: String,
    pub(crate) value: EnvValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnvValue {
    Normal(String),
    Secret(Arc<SecretString>),
}

impl EnvValue {
    pub(crate) fn sensitivity(&self) -> EnvSensitivity {
        match self {
            Self::Normal(_) => EnvSensitivity::Normal,
            Self::Secret(_) => EnvSensitivity::Secret,
        }
    }

    pub(crate) fn with_plaintext<R>(&self, f: impl FnOnce(&str) -> R) -> Result<R> {
        match self {
            Self::Normal(value) => Ok(f(value)),
            Self::Secret(value) => value.with_str(f).map_err(Into::into),
        }
    }
}

#[derive(Debug)]
pub(crate) enum EnvNode {
    Leaf(Vec<EnvEntry>),
    Internal(Vec<EnvChild>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvChild {
    pub(crate) first_name: String,
    pub(crate) offset: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct EnvLeaf {
    pub(crate) offset: u64,
    pub(crate) entries: Vec<EnvEntry>,
}

#[derive(Debug, Clone)]
pub(crate) struct EnvInternal {
    pub(crate) offset: u64,
    pub(crate) children: Vec<EnvTreeNode>,
}

#[derive(Debug, Clone)]
pub(crate) enum EnvTreeNode {
    Leaf(EnvLeaf),
    Internal(EnvInternal),
}

impl EnvTreeNode {
    pub(crate) fn offset(&self) -> u64 {
        match self {
            Self::Leaf(leaf) => leaf.offset,
            Self::Internal(internal) => internal.offset,
        }
    }

    pub(crate) fn first_name(&self) -> &str {
        match self {
            Self::Leaf(leaf) => leaf
                .entries
                .first()
                .map(|entry| entry.name.as_str())
                .unwrap_or(""),
            Self::Internal(internal) => internal
                .children
                .first()
                .map(EnvTreeNode::first_name)
                .unwrap_or(""),
        }
    }

    pub(crate) fn collect_leaves(&self, leaves: &mut Vec<EnvLeaf>) {
        match self {
            Self::Leaf(leaf) => leaves.push(leaf.clone()),
            Self::Internal(internal) => {
                for child in &internal.children {
                    child.collect_leaves(leaves);
                }
            }
        }
    }
}

pub(crate) fn env_entries_from_map(env: &BTreeMap<EnvName, EnvValue>) -> Vec<EnvEntry> {
    let mut entries = env
        .iter()
        .map(|(name, value)| EnvEntry {
            name: internal_env_name(name.as_str(), value.sensitivity()),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    entries
}

pub(crate) fn encode_env_leaf(entries: &[EnvEntry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(ENV_NODE_VERSION_WITH_SENSITIVITY);
    out.push(ENV_LEAF);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        out.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
        out.extend_from_slice(entry.name.as_bytes());
        out.push(sensitivity_tag(entry.value.sensitivity()));
        entry.value.with_plaintext(|value| {
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(value.as_bytes());
        })?;
    }
    if out.len() > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "env leaf exceeds maximum page size".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn encode_env_leaf_secure(entries: &[EnvEntry]) -> Result<SecureVec> {
    let mut out = SecureVec::new();
    out.try_extend_from_slice(&[ENV_NODE_VERSION_WITH_SENSITIVITY, ENV_LEAF])?;
    out.try_extend_from_slice(&(entries.len() as u32).to_le_bytes())?;
    for entry in entries {
        out.try_extend_from_slice(&(entry.name.len() as u16).to_le_bytes())?;
        out.try_extend_from_slice(entry.name.as_bytes())?;
        out.try_extend_from_slice(&[sensitivity_tag(entry.value.sensitivity())])?;
        match &entry.value {
            EnvValue::Normal(value) => {
                out.try_extend_from_slice(&(value.len() as u32).to_le_bytes())?;
                out.try_extend_from_slice(value.as_bytes())?;
            }
            EnvValue::Secret(value) => {
                let value_len = value.with_str(str::len)?;
                out.try_extend_from_slice(&(value_len as u32).to_le_bytes())?;
                value.append_to_secure_vec(&mut out)?;
            }
        }
    }
    if out.len() > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "env leaf exceeds maximum page size".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn encode_env_internal(children: &[EnvChild]) -> Result<Vec<u8>> {
    let routing_children = children
        .iter()
        .map(|child| PageTreeChild {
            first_key: child.first_name.clone(),
            offset: child.offset,
        })
        .collect::<Vec<_>>();
    let mut out = Vec::new();
    out.push(ENV_NODE_VERSION);
    out.push(ENV_INTERNAL);
    out.extend_from_slice(&encode_page_tree_children(&routing_children));
    if out.len() > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "env internal node exceeds maximum page size".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn env_leaf_groups(entries: &[EnvEntry]) -> Result<Vec<&[EnvEntry]>> {
    let mut groups = Vec::new();
    let mut start = 0usize;
    while start < entries.len() {
        let class = internal_env_class(&entries[start].name)?;
        let mut end = start + 1;
        while end < entries.len() && internal_env_class(&entries[end].name)? == class {
            end += 1;
        }
        groups.extend(group_by_encoded_size(
            &entries[start..end],
            ENV_NODE_PREFIX_BYTES + ENTRY_COUNT_BYTES,
            env_entry_encoded_len,
            "env entry",
        )?);
        start = end;
    }
    Ok(groups)
}

pub(crate) fn env_child_groups(children: &[EnvChild]) -> Result<Vec<&[EnvChild]>> {
    group_by_encoded_size(
        children,
        ENV_NODE_PREFIX_BYTES + CHILD_COUNT_BYTES,
        env_child_encoded_len,
        "env child",
    )
}

pub(crate) fn decode_env_node_secure(payload: &SecureVec) -> Result<EnvNode> {
    let parsed = secure_read_access(|access| {
        payload.with_bytes_in(access, |payload| {
            if payload.len() < ENV_NODE_PREFIX_BYTES {
                return Err(Error::CorruptRecord);
            }
            match payload[0] {
                ENV_NODE_VERSION | ENV_NODE_VERSION_WITH_SENSITIVITY => match payload[1] {
                    ENV_LEAF => decode_env_leaf_secure_metadata(payload, payload[0]),
                    ENV_INTERNAL => Ok(SecureEnvNodeMetadata::Internal(
                        decode_page_tree_children(&payload[2..], |key| {
                            validate_internal_env_name(key)
                        })?
                        .into_iter()
                        .map(|child| EnvChild {
                            first_name: child.first_key,
                            offset: child.offset,
                        })
                        .collect(),
                    )),
                    _ => Err(Error::CorruptRecord),
                },
                _ => Err(Error::CorruptRecord),
            }
        })
    })??;
    match parsed {
        SecureEnvNodeMetadata::Internal(children) => Ok(EnvNode::Internal(children)),
        SecureEnvNodeMetadata::Leaf(parsed_entries) => {
            let mut entries = Vec::with_capacity(parsed_entries.len());
            for entry in parsed_entries {
                let value = match entry.value {
                    ParsedEnvValue::Normal(value) => EnvValue::Normal(value),
                    ParsedEnvValue::Secret { offset, len } => {
                        let bytes = payload.try_clone_range(offset, len)?;
                        EnvValue::Secret(Arc::new(SecretString::from_secure_vec(bytes)))
                    }
                };
                entries.push(EnvEntry {
                    name: entry.name,
                    value,
                });
            }
            Ok(EnvNode::Leaf(entries))
        }
    }
}

enum SecureEnvNodeMetadata {
    Leaf(Vec<ParsedEnvEntry>),
    Internal(Vec<EnvChild>),
}

struct ParsedEnvEntry {
    name: String,
    value: ParsedEnvValue,
}

enum ParsedEnvValue {
    Normal(String),
    Secret { offset: usize, len: usize },
}

fn decode_env_leaf_secure_metadata(payload: &[u8], version: u8) -> Result<SecureEnvNodeMetadata> {
    if payload.len() < ENV_NODE_PREFIX_BYTES + ENTRY_COUNT_BYTES {
        return Err(Error::CorruptRecord);
    }
    let mut offset = ENV_NODE_PREFIX_BYTES;
    let count = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
    offset += ENTRY_COUNT_BYTES;
    if count > (payload.len() - ENV_NODE_PREFIX_BYTES - ENTRY_COUNT_BYTES) / 6 {
        return Err(Error::CorruptRecord);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 2 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let name_len = u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if offset + name_len > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let stored_name = std::str::from_utf8(&payload[offset..offset + name_len])
            .map_err(|_| Error::CorruptRecord)?;
        validate_internal_env_name(stored_name)?;
        offset += name_len;
        let sensitivity = if version == ENV_NODE_VERSION_WITH_SENSITIVITY {
            if offset + 1 > payload.len() {
                return Err(Error::CorruptRecord);
            }
            let sensitivity = sensitivity_from_tag(payload[offset])?;
            offset += 1;
            sensitivity
        } else {
            EnvSensitivity::Normal
        };
        if offset + 4 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let value_len =
            u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + value_len > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let value = std::str::from_utf8(&payload[offset..offset + value_len])
            .map_err(|_| Error::CorruptRecord)?;
        validate_env_value_ref(value)?;
        let (name, sensitivity) = public_env_name_and_sensitivity(stored_name, sensitivity)?;
        let value = match sensitivity {
            EnvSensitivity::Normal => ParsedEnvValue::Normal(value.to_string()),
            EnvSensitivity::Secret => ParsedEnvValue::Secret {
                offset,
                len: value_len,
            },
        };
        offset += value_len;
        entries.push(ParsedEnvEntry { name, value });
    }
    if offset != payload.len() {
        return Err(Error::CorruptRecord);
    }
    for pair in entries.windows(2) {
        if pair[0].name >= pair[1].name {
            return Err(Error::CorruptRecord);
        }
    }
    Ok(SecureEnvNodeMetadata::Leaf(entries))
}

fn env_entry_encoded_len(entry: &EnvEntry) -> usize {
    2 + entry.name.len()
        + 1
        + 4
        + entry
            .value
            .with_plaintext(str::len)
            .expect("env value is valid while grouping")
}

fn env_child_encoded_len(child: &EnvChild) -> usize {
    page_tree_child_encoded_len(&PageTreeChild {
        first_key: child.first_name.clone(),
        offset: child.offset,
    })
}

fn sensitivity_tag(sensitivity: EnvSensitivity) -> u8 {
    match sensitivity {
        EnvSensitivity::Normal => 0,
        EnvSensitivity::Secret => 1,
    }
}

fn sensitivity_from_tag(tag: u8) -> Result<EnvSensitivity> {
    match tag {
        0 => Ok(EnvSensitivity::Normal),
        1 => Ok(EnvSensitivity::Secret),
        _ => Err(Error::CorruptRecord),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvStorageClass {
    Plain,
    Secret,
    Legacy,
}

fn internal_env_name(name: &str, sensitivity: EnvSensitivity) -> String {
    match sensitivity {
        EnvSensitivity::Normal => format!("{ENV_PLAIN_PREFIX}{name}"),
        EnvSensitivity::Secret => format!("{ENV_SECRET_PREFIX}{name}"),
    }
}

fn internal_env_class(name: &str) -> Result<EnvStorageClass> {
    if name.starts_with(ENV_PLAIN_PREFIX) {
        Ok(EnvStorageClass::Plain)
    } else if name.starts_with(ENV_SECRET_PREFIX) {
        Ok(EnvStorageClass::Secret)
    } else {
        validate_env_name(name)?;
        Ok(EnvStorageClass::Legacy)
    }
}

fn validate_internal_env_name(name: &str) -> Result<()> {
    match internal_env_class(name)? {
        EnvStorageClass::Plain => {
            validate_env_name(&name[ENV_PLAIN_PREFIX.len()..])?;
        }
        EnvStorageClass::Secret => {
            validate_env_name(&name[ENV_SECRET_PREFIX.len()..])?;
        }
        EnvStorageClass::Legacy => {}
    }
    Ok(())
}

fn public_env_name_and_sensitivity(
    name: &str,
    encoded_sensitivity: EnvSensitivity,
) -> Result<(String, EnvSensitivity)> {
    if let Some(name) = name.strip_prefix(ENV_PLAIN_PREFIX) {
        let name = EnvName::new(name)?;
        if encoded_sensitivity != EnvSensitivity::Normal {
            return Err(Error::CorruptRecord);
        }
        return Ok((name.as_str().to_string(), EnvSensitivity::Normal));
    }
    if let Some(name) = name.strip_prefix(ENV_SECRET_PREFIX) {
        let name = EnvName::new(name)?;
        if encoded_sensitivity != EnvSensitivity::Secret {
            return Err(Error::CorruptRecord);
        }
        return Ok((name.as_str().to_string(), EnvSensitivity::Secret));
    }
    Ok((
        EnvName::new(name)?.as_str().to_string(),
        encoded_sensitivity,
    ))
}
