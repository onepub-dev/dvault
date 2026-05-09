use crate::constants::{DEFAULT_MAX_SEGMENT_BODY_BYTES, HEADER_LEN};
use crate::manifest_codec::{decode_manifest_entries, encode_manifest_entries};
use crate::manifest_entry::ManifestEntry;
use crate::{Error, Result};

const TOC_NODE_VERSION: u8 = 1;
const TOC_LEAF: u8 = 1;
const TOC_INTERNAL: u8 = 2;
pub(crate) const TOC_MIN_FILL_PERCENT: usize = 30;
const TOC_NODE_PREFIX_BYTES: usize = 2;
const ENTRY_COUNT_BYTES: usize = 4;
const CHILD_COUNT_BYTES: usize = 4;

#[derive(Debug)]
pub(crate) enum TocNode {
    Leaf(Vec<ManifestEntry>),
    Internal(Vec<TocChild>),
}

#[derive(Debug, Clone)]
pub(crate) struct TocChild {
    pub(crate) first_path: String,
    pub(crate) offset: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct TocLeaf {
    pub(crate) offset: u64,
    pub(crate) entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone)]
pub(crate) struct TocInternal {
    pub(crate) offset: u64,
    pub(crate) children: Vec<TocTreeNode>,
}

#[derive(Debug, Clone)]
pub(crate) enum TocTreeNode {
    Leaf(TocLeaf),
    Internal(TocInternal),
}

impl TocTreeNode {
    pub(crate) fn offset(&self) -> u64 {
        match self {
            Self::Leaf(leaf) => leaf.offset,
            Self::Internal(internal) => internal.offset,
        }
    }

    pub(crate) fn first_path(&self) -> &str {
        match self {
            Self::Leaf(leaf) => leaf
                .entries
                .first()
                .map(|entry| entry.path.as_str())
                .unwrap_or(""),
            Self::Internal(internal) => internal
                .children
                .first()
                .map(TocTreeNode::first_path)
                .unwrap_or(""),
        }
    }

    pub(crate) fn collect_leaves(&self, leaves: &mut Vec<TocLeaf>) {
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

pub(crate) fn encode_toc_leaf(entries: &[ManifestEntry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(TOC_NODE_VERSION);
    out.push(TOC_LEAF);
    out.extend_from_slice(&encode_manifest_entries(entries));
    if out.len() > DEFAULT_MAX_SEGMENT_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "TOC leaf exceeds maximum segment size".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn encode_toc_internal(children: &[TocChild]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(TOC_NODE_VERSION);
    out.push(TOC_INTERNAL);
    out.extend_from_slice(&(children.len() as u32).to_le_bytes());
    for child in children {
        out.extend_from_slice(&(child.first_path.len() as u16).to_le_bytes());
        out.extend_from_slice(child.first_path.as_bytes());
        out.extend_from_slice(&child.offset.to_le_bytes());
    }
    if out.len() > DEFAULT_MAX_SEGMENT_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "TOC internal node exceeds maximum segment size".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn toc_leaf_groups(entries: &[ManifestEntry]) -> Result<Vec<&[ManifestEntry]>> {
    group_by_encoded_size(entries, leaf_base_len(), manifest_entry_encoded_len)
}

pub(crate) fn toc_child_groups(children: &[TocChild]) -> Result<Vec<&[TocChild]>> {
    group_by_encoded_size(children, internal_base_len(), toc_child_encoded_len)
}

pub(crate) fn toc_leaf_fill_percent(entries: &[ManifestEntry]) -> usize {
    encoded_leaf_len(entries).saturating_mul(100) / DEFAULT_MAX_SEGMENT_BODY_BYTES
}

pub(crate) fn encoded_leaf_len(entries: &[ManifestEntry]) -> usize {
    leaf_base_len()
        + entries
            .iter()
            .map(manifest_entry_encoded_len)
            .sum::<usize>()
}

fn group_by_encoded_size<T>(
    items: &[T],
    base_len: usize,
    item_len: impl Fn(&T) -> usize,
) -> Result<Vec<&[T]>> {
    if items.is_empty() {
        return Ok(Vec::new());
    }

    let mut groups = Vec::new();
    let mut start = 0usize;
    let mut current_len = base_len;
    for (index, item) in items.iter().enumerate() {
        let len = item_len(item);
        if base_len + len > DEFAULT_MAX_SEGMENT_BODY_BYTES {
            return Err(Error::SecurityLimitExceeded(
                "TOC item exceeds maximum segment size".to_string(),
            ));
        }
        if index > start && current_len + len > DEFAULT_MAX_SEGMENT_BODY_BYTES {
            groups.push(&items[start..index]);
            start = index;
            current_len = base_len;
        }
        current_len += len;
    }
    groups.push(&items[start..]);
    Ok(groups)
}

fn leaf_base_len() -> usize {
    TOC_NODE_PREFIX_BYTES + ENTRY_COUNT_BYTES
}

fn internal_base_len() -> usize {
    TOC_NODE_PREFIX_BYTES + CHILD_COUNT_BYTES
}

fn manifest_entry_encoded_len(entry: &ManifestEntry) -> usize {
    2 + entry.path.len()
        + 8
        + 8
        + 8
        + 1
        + 1
        + 4
        + 2
        + entry.symlink_target.as_ref().map_or(0, String::len)
        + 4
        + entry
            .chunks
            .iter()
            .map(|chunk| 40 + chunk.fragments.len() * 40)
            .sum::<usize>()
}

fn toc_child_encoded_len(child: &TocChild) -> usize {
    2 + child.first_path.len() + 8
}

pub(crate) fn decode_toc_node(payload: &[u8]) -> Result<TocNode> {
    if payload.len() < 2 || payload[0] != TOC_NODE_VERSION {
        return Err(Error::CorruptRecord);
    }
    match payload[1] {
        TOC_LEAF => {
            let entries = decode_manifest_entries(&payload[2..])?;
            validate_leaf_entries(&entries)?;
            Ok(TocNode::Leaf(entries))
        }
        TOC_INTERNAL => decode_toc_internal(&payload[2..]),
        _ => Err(Error::CorruptRecord),
    }
}

fn validate_leaf_entries(entries: &[ManifestEntry]) -> Result<()> {
    for pair in entries.windows(2) {
        if pair[0].path >= pair[1].path {
            return Err(Error::CorruptRecord);
        }
    }
    Ok(())
}

fn decode_toc_internal(payload: &[u8]) -> Result<TocNode> {
    if payload.len() < 4 {
        return Err(Error::CorruptRecord);
    }
    let count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    let mut offset = 4usize;
    let mut children = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 2 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let path_len = u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if offset + path_len + 8 > payload.len() {
            return Err(Error::CorruptRecord);
        }
        let first_path = String::from_utf8(payload[offset..offset + path_len].to_vec())
            .map_err(|_| Error::CorruptRecord)?;
        crate::logical_path::validate_stored_path(&first_path)?;
        offset += path_len;
        let child_offset = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
        if child_offset < HEADER_LEN as u64 {
            return Err(Error::CorruptRecord);
        }
        offset += 8;
        children.push(TocChild {
            first_path,
            offset: child_offset,
        });
    }
    if offset != payload.len() || children.is_empty() {
        return Err(Error::CorruptRecord);
    }
    for pair in children.windows(2) {
        if pair[0].first_path >= pair[1].first_path {
            return Err(Error::CorruptRecord);
        }
    }
    Ok(TocNode::Internal(children))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_FILE_PERMISSIONS;
    use crate::manifest_entry::ManifestEntry;
    use crate::node_kind::NodeKind;

    #[test]
    fn toc_leaf_decode_rejects_tampered_paths() {
        let entry = ManifestEntry {
            path: "/safe/../evil.txt".to_string(),
            len: 1,
            record_offset: 64,
            record_len: 64,
            deleted: false,
            node_kind: NodeKind::File,
            permissions: DEFAULT_FILE_PERMISSIONS,
            symlink_target: None,
            chunks: Vec::new(),
        };
        let payload = encode_toc_leaf(&[entry]).unwrap();
        assert!(matches!(
            decode_toc_node(&payload),
            Err(Error::InvalidPath(_))
        ));
    }

    #[test]
    fn toc_internal_decode_rejects_tampered_separator_paths() {
        let payload = encode_toc_internal(&[TocChild {
            first_path: "/C:/Users/evil.txt".to_string(),
            offset: 64,
        }])
        .unwrap();
        assert!(matches!(
            decode_toc_node(&payload),
            Err(Error::InvalidPath(_))
        ));
    }

    #[test]
    fn toc_leaf_decode_rejects_unsorted_or_duplicate_paths() {
        let mut entries = vec![entry("/b.txt"), entry("/a.txt")];
        let payload = encode_toc_leaf(&entries).unwrap();
        assert!(matches!(
            decode_toc_node(&payload),
            Err(Error::CorruptRecord)
        ));

        entries = vec![entry("/a.txt"), entry("/a.txt")];
        let payload = encode_toc_leaf(&entries).unwrap();
        assert!(matches!(
            decode_toc_node(&payload),
            Err(Error::CorruptRecord)
        ));
    }

    #[test]
    fn toc_internal_decode_rejects_unsorted_duplicate_or_zero_offsets() {
        let payload = encode_toc_internal(&[
            TocChild {
                first_path: "/b.txt".to_string(),
                offset: 128,
            },
            TocChild {
                first_path: "/a.txt".to_string(),
                offset: 256,
            },
        ])
        .unwrap();
        assert!(matches!(
            decode_toc_node(&payload),
            Err(Error::CorruptRecord)
        ));

        let payload = encode_toc_internal(&[
            TocChild {
                first_path: "/a.txt".to_string(),
                offset: 128,
            },
            TocChild {
                first_path: "/a.txt".to_string(),
                offset: 256,
            },
        ])
        .unwrap();
        assert!(matches!(
            decode_toc_node(&payload),
            Err(Error::CorruptRecord)
        ));

        let payload = encode_toc_internal(&[TocChild {
            first_path: "/a.txt".to_string(),
            offset: 0,
        }])
        .unwrap();
        assert!(matches!(
            decode_toc_node(&payload),
            Err(Error::CorruptRecord)
        ));
    }

    #[test]
    fn toc_internal_numeric_fields_are_little_endian() {
        let children = vec![TocChild {
            first_path: "/a".to_string(),
            offset: 0x0102_0304_0506_0708,
        }];
        let encoded = encode_toc_internal(&children).unwrap();

        assert_eq!(&encoded[0..2], &[TOC_NODE_VERSION, TOC_INTERNAL]);
        assert_eq!(&encoded[2..6], &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(&encoded[6..8], &[0x02, 0x00]);
        assert_eq!(&encoded[8..10], b"/a");
        assert_eq!(
            &encoded[10..18],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );

        let TocNode::Internal(decoded) = decode_toc_node(&encoded).unwrap() else {
            panic!("expected internal node");
        };
        assert_eq!(decoded[0].offset, 0x0102_0304_0506_0708);
        assert_eq!(decoded[0].first_path, "/a");
    }

    #[test]
    fn toc_leaf_groups_are_sized_by_encoded_bytes() {
        let entries = (0..6000)
            .map(|i| ManifestEntry {
                path: format!("/many/file-{i:04}.txt"),
                len: 1,
                record_offset: 64,
                record_len: 64,
                deleted: false,
                node_kind: NodeKind::File,
                permissions: DEFAULT_FILE_PERMISSIONS,
                symlink_target: None,
                chunks: Vec::new(),
            })
            .collect::<Vec<_>>();

        let groups = toc_leaf_groups(&entries).unwrap();
        assert!(!groups.is_empty());
        for group in groups {
            assert!(encode_toc_leaf(group).unwrap().len() <= DEFAULT_MAX_SEGMENT_BODY_BYTES);
        }
    }

    fn entry(path: &str) -> ManifestEntry {
        ManifestEntry {
            path: path.to_string(),
            len: 1,
            record_offset: 64,
            record_len: 64,
            deleted: false,
            node_kind: NodeKind::File,
            permissions: DEFAULT_FILE_PERMISSIONS,
            symlink_target: None,
            chunks: Vec::new(),
        }
    }
}
