use std::collections::BTreeMap;

use crate::constants::DEFAULT_METADATA_MAX_PAGE_BODY_BYTES;
use crate::page_tree::{
    decode_page_tree_children, encode_page_tree_children, group_by_encoded_size,
    page_tree_child_encoded_len, PageTreeChild,
};
use crate::security::{validate_env_name, validate_env_value};
use crate::{Error, Result};

const ENV_NODE_VERSION: u8 = 1;
const ENV_LEAF: u8 = 1;
const ENV_INTERNAL: u8 = 2;
const ENV_NODE_PREFIX_BYTES: usize = 2;
const ENTRY_COUNT_BYTES: usize = 4;
const CHILD_COUNT_BYTES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvEntry {
    pub(crate) name: String,
    pub(crate) value: String,
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

pub(crate) fn env_entries_from_map(env: &BTreeMap<String, String>) -> Vec<EnvEntry> {
    env.iter()
        .map(|(name, value)| EnvEntry {
            name: name.clone(),
            value: value.clone(),
        })
        .collect()
}

pub(crate) fn encode_env_leaf(entries: &[EnvEntry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(ENV_NODE_VERSION);
    out.push(ENV_LEAF);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        out.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
        out.extend_from_slice(entry.name.as_bytes());
        out.extend_from_slice(&(entry.value.len() as u32).to_le_bytes());
        out.extend_from_slice(entry.value.as_bytes());
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
    group_by_encoded_size(
        entries,
        ENV_NODE_PREFIX_BYTES + ENTRY_COUNT_BYTES,
        env_entry_encoded_len,
        "env entry",
    )
}

pub(crate) fn env_child_groups(children: &[EnvChild]) -> Result<Vec<&[EnvChild]>> {
    group_by_encoded_size(
        children,
        ENV_NODE_PREFIX_BYTES + CHILD_COUNT_BYTES,
        env_child_encoded_len,
        "env child",
    )
}

pub(crate) fn decode_env_node(payload: &[u8]) -> Result<EnvNode> {
    if payload.len() < ENV_NODE_PREFIX_BYTES || payload[0] != ENV_NODE_VERSION {
        return Err(Error::CorruptRecord);
    }
    match payload[1] {
        ENV_LEAF => decode_env_leaf(&payload[2..]),
        ENV_INTERNAL => Ok(EnvNode::Internal(
            decode_page_tree_children(&payload[2..], |key| validate_env_name(key).map(|_| ()))?
                .into_iter()
                .map(|child| EnvChild {
                    first_name: child.first_key,
                    offset: child.offset,
                })
                .collect(),
        )),
        _ => Err(Error::CorruptRecord),
    }
}

fn decode_env_leaf(payload: &[u8]) -> Result<EnvNode> {
    if payload.len() < ENTRY_COUNT_BYTES {
        return Err(Error::CorruptRecord);
    }
    let count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    if count > (payload.len() - ENTRY_COUNT_BYTES) / 6 {
        return Err(Error::CorruptRecord);
    }
    let mut offset = ENTRY_COUNT_BYTES;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 2 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let name_len = u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if offset + name_len + 4 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let name = std::str::from_utf8(&payload[offset..offset + name_len])
            .map_err(|_| Error::CorruptRecord)?;
        let name = validate_env_name(name)?;
        offset += name_len;
        let value_len =
            u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + value_len > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let value = std::str::from_utf8(&payload[offset..offset + value_len])
            .map_err(|_| Error::CorruptRecord)?;
        let value = validate_env_value(value)?;
        offset += value_len;
        entries.push(EnvEntry { name, value });
    }
    if offset != payload.len() {
        return Err(Error::CorruptRecord);
    }
    for pair in entries.windows(2) {
        if pair[0].name >= pair[1].name {
            return Err(Error::CorruptRecord);
        }
    }
    Ok(EnvNode::Leaf(entries))
}

fn env_entry_encoded_len(entry: &EnvEntry) -> usize {
    2 + entry.name.len() + 4 + entry.value.len()
}

fn env_child_encoded_len(child: &EnvChild) -> usize {
    page_tree_child_encoded_len(&PageTreeChild {
        first_key: child.first_name.clone(),
        offset: child.offset,
    })
}
