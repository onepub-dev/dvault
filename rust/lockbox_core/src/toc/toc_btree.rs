use crate::constants::DEFAULT_METADATA_MAX_PAGE_BODY_BYTES;
use crate::page_tree::{
    decode_page_tree_children, encode_page_tree_children, group_by_encoded_size,
    page_tree_child_encoded_len, PageTreeChild,
};
use crate::toc_codec::{
    decode_toc_entries, encode_toc_entries, encoded_toc_entries_len, TocEntriesLenEstimator,
};
use crate::toc_entry::TocEntry;
use crate::{Error, LockboxPath, Result};

const TOC_NODE_VERSION: u8 = 1;
const TOC_LEAF: u8 = 1;
const TOC_INTERNAL: u8 = 2;
pub(crate) const TOC_MIN_FILL_PERCENT: usize = 30;
const TOC_NODE_PREFIX_BYTES: usize = 2;

#[derive(Debug)]
pub(crate) enum TocNode {
    Leaf(Vec<TocEntry>),
    Internal(Vec<TocChild>),
}

#[derive(Debug, Clone)]
pub(crate) struct TocChild {
    pub(crate) first_path: LockboxPath,
    pub(crate) offset: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct TocLeaf {
    pub(crate) offset: u64,
    pub(crate) entries: Vec<TocEntry>,
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

pub(crate) fn encode_toc_leaf(entries: &[TocEntry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(TOC_NODE_VERSION);
    out.push(TOC_LEAF);
    out.extend_from_slice(&encode_toc_entries(entries));
    if out.len() > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "TOC leaf exceeds maximum page size".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn encode_toc_internal(children: &[TocChild]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(TOC_NODE_VERSION);
    out.push(TOC_INTERNAL);
    let routing_children = children
        .iter()
        .map(|child| PageTreeChild {
            first_key: child.first_path.as_str().to_string(),
            offset: child.offset,
        })
        .collect::<Vec<_>>();
    out.extend_from_slice(&encode_page_tree_children(&routing_children));
    if out.len() > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "TOC internal node exceeds maximum page size".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn toc_leaf_groups(entries: &[TocEntry]) -> Result<Vec<&[TocEntry]>> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let mut groups = Vec::new();
    let mut start = 0usize;
    let mut group_len = TocEntriesLenEstimator::new();
    for (index, entry) in entries.iter().enumerate() {
        let single_len = leaf_base_len() + encoded_toc_entries_len(std::slice::from_ref(entry));
        if single_len > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
            return Err(Error::SecurityLimitExceeded(
                "TOC entry exceeds maximum page size".to_string(),
            ));
        }

        group_len.push(entry);
        let candidate_len = leaf_base_len() + group_len.encoded_len();
        if group_len.count() > 1 && candidate_len > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
            groups.push(&entries[start..index]);
            start = index;
            group_len.clear();
            group_len.push(entry);
        }
    }
    groups.push(&entries[start..]);
    Ok(groups)
}

pub(crate) fn toc_child_groups(children: &[TocChild]) -> Result<Vec<&[TocChild]>> {
    group_by_encoded_size(
        children,
        internal_base_len(),
        toc_child_encoded_len,
        "TOC child",
    )
}

pub(crate) fn toc_leaf_fill_percent(entries: &[TocEntry]) -> usize {
    encoded_leaf_len(entries).saturating_mul(100) / DEFAULT_METADATA_MAX_PAGE_BODY_BYTES
}

pub(crate) fn encoded_leaf_len(entries: &[TocEntry]) -> usize {
    leaf_base_len() + encoded_toc_entries_len(entries)
}

fn leaf_base_len() -> usize {
    TOC_NODE_PREFIX_BYTES
}

fn internal_base_len() -> usize {
    TOC_NODE_PREFIX_BYTES + 4
}

fn toc_child_encoded_len(child: &TocChild) -> usize {
    page_tree_child_encoded_len(&PageTreeChild {
        first_key: child.first_path.as_str().to_string(),
        offset: child.offset,
    })
}

pub(crate) fn decode_toc_node(payload: &[u8]) -> Result<TocNode> {
    if payload.len() < 2 || payload[0] != TOC_NODE_VERSION {
        return Err(Error::CorruptRecord);
    }
    match payload[1] {
        TOC_LEAF => {
            let entries = decode_toc_entries(&payload[2..])?;
            validate_leaf_entries(&entries)?;
            Ok(TocNode::Leaf(entries))
        }
        TOC_INTERNAL => decode_toc_internal(&payload[2..]),
        _ => Err(Error::CorruptRecord),
    }
}

fn validate_leaf_entries(entries: &[TocEntry]) -> Result<()> {
    for pair in entries.windows(2) {
        if pair[0].path >= pair[1].path {
            return Err(Error::CorruptRecord);
        }
    }
    Ok(())
}

fn decode_toc_internal(payload: &[u8]) -> Result<TocNode> {
    let children = decode_page_tree_children(payload, |key| {
        LockboxPath::from_stored(key, false).map(|_| ())
    })?
    .into_iter()
    .map(|child| {
        Ok(TocChild {
            first_path: LockboxPath::from_stored(&child.first_key, false)?,
            offset: child.offset,
        })
    })
    .collect::<Result<Vec<_>>>()?;
    Ok(TocNode::Internal(children))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_FILE_PERMISSIONS;
    use crate::node_kind::NodeKind;
    use crate::toc_entry::TocEntry;

    #[test]
    fn toc_leaf_decode_rejects_tampered_paths() {
        let entry = TocEntry {
            path: LockboxPath::from_unchecked_for_test("/safe/../evil.txt"),
            len: 1,
            record_offset: 64,
            record_len: 64,
            record_object_id: 1,
            deleted: false,
            node_kind: NodeKind::File,
            permissions: DEFAULT_FILE_PERMISSIONS,
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
            first_path: LockboxPath::from_unchecked_for_test("/C:/Users/evil.txt"),
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
                first_path: LockboxPath::new("/b.txt").unwrap(),
                offset: 128,
            },
            TocChild {
                first_path: LockboxPath::new("/a.txt").unwrap(),
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
                first_path: LockboxPath::new("/a.txt").unwrap(),
                offset: 128,
            },
            TocChild {
                first_path: LockboxPath::new("/a.txt").unwrap(),
                offset: 256,
            },
        ])
        .unwrap();
        assert!(matches!(
            decode_toc_node(&payload),
            Err(Error::CorruptRecord)
        ));

        let payload = encode_toc_internal(&[TocChild {
            first_path: LockboxPath::new("/a.txt").unwrap(),
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
            first_path: LockboxPath::new("/a").unwrap(),
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
            .map(|i| TocEntry {
                path: LockboxPath::new(format!("/many/file-{i:04}.txt")).unwrap(),
                len: 1,
                record_offset: 64,
                record_len: 64,
                record_object_id: 1,
                deleted: false,
                node_kind: NodeKind::File,
                permissions: DEFAULT_FILE_PERMISSIONS,
                chunks: Vec::new(),
            })
            .collect::<Vec<_>>();

        let groups = toc_leaf_groups(&entries).unwrap();
        assert!(!groups.is_empty());
        for group in groups {
            assert!(encode_toc_leaf(group).unwrap().len() <= DEFAULT_METADATA_MAX_PAGE_BODY_BYTES);
        }
    }

    fn entry(path: &str) -> TocEntry {
        TocEntry {
            path: LockboxPath::new(path).unwrap(),
            len: 1,
            record_offset: 64,
            record_len: 64,
            record_object_id: 1,
            deleted: false,
            node_kind: NodeKind::File,
            permissions: DEFAULT_FILE_PERMISSIONS,
            chunks: Vec::new(),
        }
    }
}
