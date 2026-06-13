use std::collections::BTreeMap;
use std::sync::Arc;

use crate::checked::{read_u16_le, read_u32_le};
use crate::constants::DEFAULT_METADATA_MAX_PAGE_BODY_BYTES;
use crate::page_tree::{
    decode_page_tree_children, encode_page_tree_children, group_by_encoded_size,
    page_tree_child_encoded_len, PageTreeChild,
};
use crate::secret_vec::{secure_read_access, SecureVec};
use crate::security::{validate_variable_name, validate_variable_value_ref};
use crate::{Error, Result, SecretString, VariableName, VariableSensitivity};

const VARIABLE_NODE_VERSION: u8 = 1;
const VARIABLE_NODE_VERSION_WITH_SENSITIVITY: u8 = 2;
const VARIABLE_LEAF: u8 = 1;
const VARIABLE_INTERNAL: u8 = 2;
const VARIABLE_NODE_PREFIX_BYTES: usize = 2;
const ENTRY_COUNT_BYTES: usize = 4;
const CHILD_COUNT_BYTES: usize = 4;
const VARIABLE_PLAIN_PREFIX: &str = ".plain/";
const VARIABLE_SECRET_PREFIX: &str = ".secret/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VariableEntry {
    pub(crate) name: String,
    pub(crate) value: VariableValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VariableValue {
    Normal(String),
    Secret(Arc<SecretString>),
}

impl VariableValue {
    pub(crate) fn sensitivity(&self) -> VariableSensitivity {
        match self {
            Self::Normal(_) => VariableSensitivity::Normal,
            Self::Secret(_) => VariableSensitivity::Secret,
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
pub(crate) enum VariableNode {
    Leaf(Vec<VariableEntry>),
    Internal(Vec<VariableChild>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VariableChild {
    pub(crate) first_name: String,
    pub(crate) offset: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct VariableLeaf {
    pub(crate) offset: u64,
    pub(crate) entries: Vec<VariableEntry>,
}

#[derive(Debug, Clone)]
pub(crate) struct VariableInternal {
    pub(crate) offset: u64,
    pub(crate) children: Vec<VariableTreeNode>,
}

#[derive(Debug, Clone)]
pub(crate) enum VariableTreeNode {
    Leaf(VariableLeaf),
    Internal(VariableInternal),
}

impl VariableTreeNode {
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
                .map(VariableTreeNode::first_name)
                .unwrap_or(""),
        }
    }

    pub(crate) fn collect_leaves(&self, leaves: &mut Vec<VariableLeaf>) {
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

pub(crate) fn variable_entries_from_map(
    variables: &BTreeMap<VariableName, VariableValue>,
) -> Vec<VariableEntry> {
    let mut entries = variables
        .iter()
        .map(|(name, value)| VariableEntry {
            name: internal_variable_name(name.as_str(), value.sensitivity()),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    entries
}

pub(crate) fn encode_variable_leaf(entries: &[VariableEntry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(VARIABLE_NODE_VERSION_WITH_SENSITIVITY);
    out.push(VARIABLE_LEAF);
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
            "variable leaf exceeds maximum page size".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn encode_variable_leaf_secure(entries: &[VariableEntry]) -> Result<SecureVec> {
    let mut out = SecureVec::new();
    out.try_extend_from_slice(&[VARIABLE_NODE_VERSION_WITH_SENSITIVITY, VARIABLE_LEAF])?;
    out.try_extend_from_slice(&(entries.len() as u32).to_le_bytes())?;
    for entry in entries {
        out.try_extend_from_slice(&(entry.name.len() as u16).to_le_bytes())?;
        out.try_extend_from_slice(entry.name.as_bytes())?;
        out.try_extend_from_slice(&[sensitivity_tag(entry.value.sensitivity())])?;
        match &entry.value {
            VariableValue::Normal(value) => {
                out.try_extend_from_slice(&(value.len() as u32).to_le_bytes())?;
                out.try_extend_from_slice(value.as_bytes())?;
            }
            VariableValue::Secret(value) => {
                let value_len = value.with_str(str::len)?;
                out.try_extend_from_slice(&(value_len as u32).to_le_bytes())?;
                value.append_to_secure_vec(&mut out)?;
            }
        }
    }
    if out.len() > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "variable leaf exceeds maximum page size".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn encode_variable_internal(children: &[VariableChild]) -> Result<Vec<u8>> {
    let routing_children = children
        .iter()
        .map(|child| PageTreeChild {
            first_key: child.first_name.clone(),
            offset: child.offset,
        })
        .collect::<Vec<_>>();
    let mut out = Vec::new();
    out.push(VARIABLE_NODE_VERSION);
    out.push(VARIABLE_INTERNAL);
    out.extend_from_slice(&encode_page_tree_children(&routing_children));
    if out.len() > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "variable internal node exceeds maximum page size".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn variable_leaf_groups(entries: &[VariableEntry]) -> Result<Vec<&[VariableEntry]>> {
    let mut groups = Vec::new();
    let mut start = 0usize;
    while start < entries.len() {
        let class = internal_variable_class(&entries[start].name)?;
        let mut end = start + 1;
        while end < entries.len() && internal_variable_class(&entries[end].name)? == class {
            end += 1;
        }
        groups.extend(group_by_encoded_size(
            &entries[start..end],
            VARIABLE_NODE_PREFIX_BYTES + ENTRY_COUNT_BYTES,
            variable_entry_encoded_len,
            "variable entry",
        )?);
        start = end;
    }
    Ok(groups)
}

pub(crate) fn variable_child_groups(children: &[VariableChild]) -> Result<Vec<&[VariableChild]>> {
    group_by_encoded_size(
        children,
        VARIABLE_NODE_PREFIX_BYTES + CHILD_COUNT_BYTES,
        variable_child_encoded_len,
        "variable child",
    )
}

pub(crate) fn decode_variable_node_secure(payload: &SecureVec) -> Result<VariableNode> {
    let parsed = secure_read_access(|access| {
        payload.with_bytes_in(access, |payload| {
            if payload.len() < VARIABLE_NODE_PREFIX_BYTES {
                return Err(Error::CorruptRecord);
            }
            match payload[0] {
                VARIABLE_NODE_VERSION | VARIABLE_NODE_VERSION_WITH_SENSITIVITY => {
                    match payload[1] {
                        VARIABLE_LEAF => decode_variable_leaf_secure_metadata(payload, payload[0]),
                        VARIABLE_INTERNAL => Ok(SecureVariableNodeMetadata::Internal(
                            decode_page_tree_children(&payload[2..], |key| {
                                validate_internal_variable_name(key)
                            })?
                            .into_iter()
                            .map(|child| VariableChild {
                                first_name: child.first_key,
                                offset: child.offset,
                            })
                            .collect(),
                        )),
                        _ => Err(Error::CorruptRecord),
                    }
                }
                _ => Err(Error::CorruptRecord),
            }
        })
    })??;
    match parsed {
        SecureVariableNodeMetadata::Internal(children) => Ok(VariableNode::Internal(children)),
        SecureVariableNodeMetadata::Leaf(parsed_entries) => {
            let mut entries = Vec::with_capacity(parsed_entries.len());
            for entry in parsed_entries {
                let value = match entry.value {
                    ParsedVariableValue::Normal(value) => VariableValue::Normal(value),
                    ParsedVariableValue::Secret { offset, len } => {
                        let bytes = payload.try_clone_range(offset, len)?;
                        VariableValue::Secret(Arc::new(SecretString::from_secure_vec(bytes)))
                    }
                };
                entries.push(VariableEntry {
                    name: entry.name,
                    value,
                });
            }
            Ok(VariableNode::Leaf(entries))
        }
    }
}

enum SecureVariableNodeMetadata {
    Leaf(Vec<ParsedVariableEntry>),
    Internal(Vec<VariableChild>),
}

struct ParsedVariableEntry {
    name: String,
    value: ParsedVariableValue,
}

enum ParsedVariableValue {
    Normal(String),
    Secret { offset: usize, len: usize },
}

fn decode_variable_leaf_secure_metadata(
    payload: &[u8],
    version: u8,
) -> Result<SecureVariableNodeMetadata> {
    if payload.len() < VARIABLE_NODE_PREFIX_BYTES + ENTRY_COUNT_BYTES {
        return Err(Error::CorruptRecord);
    }
    let mut offset = VARIABLE_NODE_PREFIX_BYTES;
    let count = read_u32_le(&payload[offset..offset + 4])? as usize;
    offset += ENTRY_COUNT_BYTES;
    if count > (payload.len() - VARIABLE_NODE_PREFIX_BYTES - ENTRY_COUNT_BYTES) / 6 {
        return Err(Error::CorruptRecord);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 2 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let name_len = read_u16_le(&payload[offset..offset + 2])? as usize;
        offset += 2;
        if offset + name_len > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let stored_name = std::str::from_utf8(&payload[offset..offset + name_len])
            .map_err(|_| Error::CorruptRecord)?;
        validate_internal_variable_name(stored_name)?;
        offset += name_len;
        let sensitivity = if version == VARIABLE_NODE_VERSION_WITH_SENSITIVITY {
            if offset + 1 > payload.len() {
                return Err(Error::CorruptRecord);
            }
            let sensitivity = sensitivity_from_tag(payload[offset])?;
            offset += 1;
            sensitivity
        } else {
            VariableSensitivity::Normal
        };
        if offset + 4 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let value_len = read_u32_le(&payload[offset..offset + 4])? as usize;
        offset += 4;
        if offset + value_len > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let value = std::str::from_utf8(&payload[offset..offset + value_len])
            .map_err(|_| Error::CorruptRecord)?;
        validate_variable_value_ref(value)?;
        let (name, sensitivity) = public_variable_name_and_sensitivity(stored_name, sensitivity)?;
        let value = match sensitivity {
            VariableSensitivity::Normal => ParsedVariableValue::Normal(value.to_string()),
            VariableSensitivity::Secret => ParsedVariableValue::Secret {
                offset,
                len: value_len,
            },
        };
        offset += value_len;
        entries.push(ParsedVariableEntry { name, value });
    }
    if offset != payload.len() {
        return Err(Error::CorruptRecord);
    }
    for pair in entries.windows(2) {
        if pair[0].name >= pair[1].name {
            return Err(Error::CorruptRecord);
        }
    }
    Ok(SecureVariableNodeMetadata::Leaf(entries))
}

fn variable_entry_encoded_len(entry: &VariableEntry) -> usize {
    2 + entry.name.len()
        + 1
        + 4
        + entry
            .value
            .with_plaintext(str::len)
            .unwrap_or(DEFAULT_METADATA_MAX_PAGE_BODY_BYTES)
}

fn variable_child_encoded_len(child: &VariableChild) -> usize {
    page_tree_child_encoded_len(&PageTreeChild {
        first_key: child.first_name.clone(),
        offset: child.offset,
    })
}

fn sensitivity_tag(sensitivity: VariableSensitivity) -> u8 {
    match sensitivity {
        VariableSensitivity::Normal => 0,
        VariableSensitivity::Secret => 1,
    }
}

fn sensitivity_from_tag(tag: u8) -> Result<VariableSensitivity> {
    match tag {
        0 => Ok(VariableSensitivity::Normal),
        1 => Ok(VariableSensitivity::Secret),
        _ => Err(Error::CorruptRecord),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VariableStorageClass {
    Plain,
    Secret,
    Legacy,
}

fn internal_variable_name(name: &str, sensitivity: VariableSensitivity) -> String {
    match sensitivity {
        VariableSensitivity::Normal => format!("{VARIABLE_PLAIN_PREFIX}{name}"),
        VariableSensitivity::Secret => format!("{VARIABLE_SECRET_PREFIX}{name}"),
    }
}

fn internal_variable_class(name: &str) -> Result<VariableStorageClass> {
    if name.starts_with(VARIABLE_PLAIN_PREFIX) {
        Ok(VariableStorageClass::Plain)
    } else if name.starts_with(VARIABLE_SECRET_PREFIX) {
        Ok(VariableStorageClass::Secret)
    } else {
        validate_variable_name(name)?;
        Ok(VariableStorageClass::Legacy)
    }
}

fn validate_internal_variable_name(name: &str) -> Result<()> {
    match internal_variable_class(name)? {
        VariableStorageClass::Plain => {
            validate_variable_name(&name[VARIABLE_PLAIN_PREFIX.len()..])?;
        }
        VariableStorageClass::Secret => {
            validate_variable_name(&name[VARIABLE_SECRET_PREFIX.len()..])?;
        }
        VariableStorageClass::Legacy => {}
    }
    Ok(())
}

fn public_variable_name_and_sensitivity(
    name: &str,
    encoded_sensitivity: VariableSensitivity,
) -> Result<(String, VariableSensitivity)> {
    if let Some(name) = name.strip_prefix(VARIABLE_PLAIN_PREFIX) {
        let name = VariableName::new(name)?;
        if encoded_sensitivity != VariableSensitivity::Normal {
            return Err(Error::CorruptRecord);
        }
        return Ok((name.as_str().to_string(), VariableSensitivity::Normal));
    }
    if let Some(name) = name.strip_prefix(VARIABLE_SECRET_PREFIX) {
        let name = VariableName::new(name)?;
        if encoded_sensitivity != VariableSensitivity::Secret {
            return Err(Error::CorruptRecord);
        }
        return Ok((name.as_str().to_string(), VariableSensitivity::Secret));
    }
    Ok((
        VariableName::new(name)?.as_str().to_string(),
        encoded_sensitivity,
    ))
}
