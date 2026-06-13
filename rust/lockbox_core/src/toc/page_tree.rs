use crate::checked::{read_u16_le, read_u32_le, read_u64_le};
use crate::constants::{DEFAULT_METADATA_MAX_PAGE_BODY_BYTES, HEADER_LEN};
use crate::{Error, Result};

const CHILD_COUNT_BYTES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PageTreeChild {
    pub(crate) first_key: String,
    pub(crate) offset: u64,
}

pub(crate) fn group_by_encoded_size<'a, T>(
    items: &'a [T],
    base_len: usize,
    item_len: impl Fn(&T) -> usize,
    item_name: &str,
) -> Result<Vec<&'a [T]>> {
    if items.is_empty() {
        return Ok(Vec::new());
    }

    let mut groups = Vec::new();
    let mut start = 0usize;
    let mut current_len = base_len;
    for (index, item) in items.iter().enumerate() {
        let len = item_len(item);
        if base_len + len > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
            return Err(Error::SecurityLimitExceeded(format!(
                "{item_name} exceeds maximum page size"
            )));
        }
        if index > start && current_len + len > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
            groups.push(&items[start..index]);
            start = index;
            current_len = base_len;
        }
        current_len += len;
    }
    groups.push(&items[start..]);
    Ok(groups)
}

pub(crate) fn encode_page_tree_children(children: &[PageTreeChild]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(children.len() as u32).to_le_bytes());
    for child in children {
        out.extend_from_slice(&(child.first_key.len() as u16).to_le_bytes());
        out.extend_from_slice(child.first_key.as_bytes());
        out.extend_from_slice(&child.offset.to_le_bytes());
    }
    out
}

pub(crate) fn decode_page_tree_children(
    payload: &[u8],
    validate_key: impl Fn(&str) -> Result<()>,
) -> Result<Vec<PageTreeChild>> {
    if payload.len() < CHILD_COUNT_BYTES {
        return Err(Error::CorruptRecord);
    }
    let count = read_u32_le(&payload[0..4])? as usize;
    if count == 0 || count > (payload.len() - CHILD_COUNT_BYTES) / 10 {
        return Err(Error::CorruptRecord);
    }
    let mut offset = CHILD_COUNT_BYTES;
    let mut children = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 2 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let key_len = read_u16_le(&payload[offset..offset + 2])? as usize;
        offset += 2;
        if offset + key_len + 8 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let first_key = String::from_utf8(payload[offset..offset + key_len].to_vec())
            .map_err(|_| Error::CorruptRecord)?;
        validate_key(&first_key)?;
        offset += key_len;
        let child_offset = read_u64_le(&payload[offset..offset + 8])?;
        if child_offset < HEADER_LEN as u64 {
            return Err(Error::CorruptRecord);
        }
        offset += 8;
        children.push(PageTreeChild {
            first_key,
            offset: child_offset,
        });
    }
    if offset != payload.len() || children.is_empty() {
        return Err(Error::CorruptRecord);
    }
    for pair in children.windows(2) {
        if pair[0].first_key >= pair[1].first_key {
            return Err(Error::CorruptRecord);
        }
    }
    Ok(children)
}

pub(crate) fn page_tree_child_encoded_len(child: &PageTreeChild) -> usize {
    2 + child.first_key.len() + 8
}
