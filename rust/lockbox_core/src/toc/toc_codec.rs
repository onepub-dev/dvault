use crate::constants::{DEFAULT_FILE_PERMISSIONS, DEFAULT_SYMLINK_PERMISSIONS};
use crate::file_chunk::{CompressionFrameSegment, FileChunk};
use crate::node_kind::NodeKind;
use crate::security::validate_permissions;
use crate::toc_entry::TocEntry;
use crate::{Error, LockboxPath, Result};

const PATH_RESTART_INTERVAL: usize = 128;
const ENTRY_FLAG_DELETED: u8 = 0x01;
const ENTRY_FLAG_SYMLINK: u8 = 0x02;
const ENTRY_FLAG_CUSTOM_PERMISSIONS: u8 = 0x04;

#[cfg(test)]
pub(crate) fn encode_toc(
    toc_entries: &std::collections::BTreeMap<LockboxPath, TocEntry>,
) -> Vec<u8> {
    encode_toc_entries(toc_entries.values())
}

pub(crate) fn encode_toc_entries<'a>(entries: impl IntoIterator<Item = &'a TocEntry>) -> Vec<u8> {
    let entries = entries.into_iter().collect::<Vec<_>>();
    let descriptors = frame_descriptors(&entries);
    let mut out = Vec::new();
    put_varint(entries.len() as u64, &mut out);
    put_varint(descriptors.len() as u64, &mut out);
    for descriptor in &descriptors {
        encode_frame_descriptor(descriptor, &mut out);
    }
    let mut previous_path = "";
    for (index, entry) in entries.iter().enumerate() {
        let default_permissions = default_permissions(entry.node_kind);
        let mut flags = 0u8;
        if entry.deleted {
            flags |= ENTRY_FLAG_DELETED;
        }
        if entry.node_kind == NodeKind::Symlink {
            flags |= ENTRY_FLAG_SYMLINK;
        }
        if entry.permissions != default_permissions {
            flags |= ENTRY_FLAG_CUSTOM_PERMISSIONS;
        }

        out.push(flags);
        encode_path(entry.path.as_str(), previous_path, index, &mut out);
        put_varint(entry.len, &mut out);
        put_varint(entry.record_offset, &mut out);
        put_varint(entry.record_len, &mut out);
        put_varint(entry.record_object_id, &mut out);
        if flags & ENTRY_FLAG_CUSTOM_PERMISSIONS != 0 {
            put_varint(entry.permissions as u64, &mut out);
        }
        put_varint(entry.chunks.len() as u64, &mut out);
        for chunk in &entry.chunks {
            let stored_path = if chunk.stored_path == entry.path.as_str() {
                ""
            } else {
                chunk.stored_path.as_str()
            };
            put_varint(stored_path.len() as u64, &mut out);
            out.extend_from_slice(stored_path.as_bytes());
            put_varint(chunk.file_offset, &mut out);
            put_varint(chunk.len, &mut out);
            put_varint(chunk.compression_frame_offset, &mut out);
            let descriptor_index = frame_descriptor_index(&descriptors, chunk).unwrap_or(0);
            put_varint(descriptor_index as u64, &mut out);
        }
        previous_path = entry.path.as_str();
    }
    out
}

pub(crate) fn encoded_toc_entries_len(entries: &[TocEntry]) -> usize {
    let descriptors = frame_descriptors(&entries.iter().collect::<Vec<_>>());
    encoded_toc_count_len(entries.len())
        + encoded_toc_count_len(descriptors.len())
        + descriptors
            .iter()
            .map(encoded_descriptor_len)
            .sum::<usize>()
        + encoded_entries_with_descriptors_len(entries, &descriptors)
}

pub(crate) fn encoded_toc_count_len(count: usize) -> usize {
    varint_len(count as u64)
}

#[derive(Debug, Default)]
pub(crate) struct TocEntriesLenEstimator {
    count: usize,
    descriptors: Vec<FrameDescriptor>,
    descriptor_len: usize,
    entries_len: usize,
    previous_path: String,
}

impl TocEntriesLenEstimator {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn count(&self) -> usize {
        self.count
    }

    pub(crate) fn clear(&mut self) {
        self.count = 0;
        self.descriptors.clear();
        self.descriptor_len = 0;
        self.entries_len = 0;
        self.previous_path.clear();
    }

    pub(crate) fn push(&mut self, entry: &TocEntry) {
        for chunk in &entry.chunks {
            if frame_descriptor_index(&self.descriptors, chunk).is_none() {
                let descriptor = FrameDescriptor::from_chunk(chunk);
                self.descriptor_len += encoded_descriptor_len(&descriptor);
                self.descriptors.push(descriptor);
            }
        }
        self.entries_len += encoded_toc_entry_len(
            entry,
            Some(&self.previous_path),
            self.count,
            &self.descriptors,
        );
        self.previous_path.clear();
        self.previous_path.push_str(entry.path.as_str());
        self.count += 1;
    }

    pub(crate) fn encoded_len(&self) -> usize {
        encoded_toc_count_len(self.count)
            + encoded_toc_count_len(self.descriptors.len())
            + self.descriptor_len
            + self.entries_len
    }
}

fn encoded_entries_with_descriptors_len(
    entries: &[TocEntry],
    descriptors: &[FrameDescriptor],
) -> usize {
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let previous_path = index
                .checked_sub(1)
                .and_then(|previous| entries.get(previous))
                .map(|entry| entry.path.as_str());
            encoded_toc_entry_len(entry, previous_path, index, descriptors)
        })
        .sum::<usize>()
}

fn encoded_toc_entry_len(
    entry: &TocEntry,
    previous_path: Option<&str>,
    index: usize,
    descriptors: &[FrameDescriptor],
) -> usize {
    let default_permissions = default_permissions(entry.node_kind);
    1 + encoded_path_len(entry.path.as_str(), previous_path.unwrap_or(""), index)
        + varint_len(entry.len)
        + varint_len(entry.record_offset)
        + varint_len(entry.record_len)
        + varint_len(entry.record_object_id)
        + if entry.permissions == default_permissions {
            0
        } else {
            varint_len(entry.permissions as u64)
        }
        + varint_len(entry.chunks.len() as u64)
        + entry
            .chunks
            .iter()
            .map(|chunk| encoded_chunk_len(entry, chunk, descriptors))
            .sum::<usize>()
}

#[cfg(test)]
pub(crate) fn decode_toc(
    payload: &[u8],
) -> Result<std::collections::BTreeMap<LockboxPath, TocEntry>> {
    Ok(decode_toc_entries(payload)?
        .into_iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect())
}

pub(crate) fn decode_toc_entries(payload: &[u8]) -> Result<Vec<TocEntry>> {
    let mut offset = 0;
    let count =
        usize::try_from(take_varint(payload, &mut offset)?).map_err(|_| Error::CorruptRecord)?;
    if count > payload.len().saturating_sub(offset) {
        return Err(Error::CorruptRecord);
    }
    let descriptor_count =
        usize::try_from(take_varint(payload, &mut offset)?).map_err(|_| Error::CorruptRecord)?;
    if descriptor_count > payload.len().saturating_sub(offset) {
        return Err(Error::CorruptRecord);
    }
    let mut descriptors = Vec::with_capacity(descriptor_count);
    for _ in 0..descriptor_count {
        descriptors.push(decode_frame_descriptor(payload, &mut offset)?);
    }

    let mut entries = Vec::with_capacity(count);
    let mut previous_path = String::new();
    for index in 0..count {
        if offset >= payload.len() {
            return Err(Error::CorruptRecord);
        }
        let flags = payload[offset];
        offset += 1;
        if flags & !(ENTRY_FLAG_DELETED | ENTRY_FLAG_SYMLINK | ENTRY_FLAG_CUSTOM_PERMISSIONS) != 0 {
            return Err(Error::CorruptRecord);
        }

        let path = decode_path(payload, &mut offset, &previous_path, index)?;
        let path = LockboxPath::from_stored(&path, false)?;
        let next_previous_path = path.as_str().to_string();
        let len = take_varint(payload, &mut offset)?;
        let record_offset = take_varint(payload, &mut offset)?;
        let record_len = take_varint(payload, &mut offset)?;
        let record_object_id = take_varint(payload, &mut offset)?;
        let deleted = flags & ENTRY_FLAG_DELETED != 0;
        let node_kind = NodeKind::from_u8(if flags & ENTRY_FLAG_SYMLINK == 0 {
            1
        } else {
            2
        })?;
        let permissions = if flags & ENTRY_FLAG_CUSTOM_PERMISSIONS == 0 {
            default_permissions(node_kind)
        } else {
            u32::try_from(take_varint(payload, &mut offset)?).map_err(|_| Error::CorruptRecord)?
        };
        let permissions = validate_permissions(permissions)?;
        let chunk_count = usize::try_from(take_varint(payload, &mut offset)?)
            .map_err(|_| Error::CorruptRecord)?;
        if chunk_count > payload.len().saturating_sub(offset) {
            return Err(Error::CorruptRecord);
        }
        let mut chunks = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            let stored_path_len = usize::try_from(take_varint(payload, &mut offset)?)
                .map_err(|_| Error::CorruptRecord)?;
            if stored_path_len > payload.len().saturating_sub(offset) {
                return Err(Error::CorruptRecord);
            }
            let stored_path = if stored_path_len == 0 {
                path.clone()
            } else {
                let stored_path =
                    String::from_utf8(payload[offset..offset + stored_path_len].to_vec())
                        .map_err(|_| Error::CorruptRecord)?;
                LockboxPath::from_stored(&stored_path, false)?
            };
            offset += stored_path_len;
            let file_offset = take_varint(payload, &mut offset)?;
            let chunk_len = take_varint(payload, &mut offset)?;
            let compression_frame_offset = take_varint(payload, &mut offset)?;
            let descriptor_index = usize::try_from(take_varint(payload, &mut offset)?)
                .map_err(|_| Error::CorruptRecord)?;
            let descriptor = descriptors
                .get(descriptor_index)
                .ok_or(Error::CorruptRecord)?;
            chunks.push(FileChunk {
                stored_path,
                file_offset,
                len: chunk_len,
                compression_frame_offset,
                compression_frame_len: descriptor.compression_frame_len,
                compressed_len: descriptor.compressed_len,
                compression: descriptor.compression,
                compression_frame_id: descriptor.compression_frame_id,
                compression_frame_digest: descriptor.compression_frame_digest,
                segments: descriptor.segments.clone(),
            });
        }
        match node_kind {
            NodeKind::Symlink if record_offset == 0 || record_len == 0 || record_object_id == 0 => {
                return Err(Error::CorruptRecord);
            }
            NodeKind::Symlink if !chunks.is_empty() => return Err(Error::CorruptRecord),
            _ => {}
        }
        entries.push(TocEntry {
            path,
            len,
            record_offset,
            record_len,
            record_object_id,
            deleted,
            node_kind,
            permissions,
            chunks,
        });
        previous_path = next_previous_path;
    }
    if offset != payload.len() {
        return Err(Error::CorruptRecord);
    }
    Ok(entries)
}

fn encode_path(path: &str, previous_path: &str, index: usize, out: &mut Vec<u8>) {
    if path_restart(index) {
        put_varint(path.len() as u64, out);
        out.extend_from_slice(path.as_bytes());
        return;
    }

    let prefix_len = common_prefix_len(previous_path, path);
    let suffix = &path.as_bytes()[prefix_len..];
    put_varint(prefix_len as u64, out);
    put_varint(suffix.len() as u64, out);
    out.extend_from_slice(suffix);
}

fn decode_path(
    payload: &[u8],
    offset: &mut usize,
    previous_path: &str,
    index: usize,
) -> Result<String> {
    if path_restart(index) {
        let path_len =
            usize::try_from(take_varint(payload, offset)?).map_err(|_| Error::CorruptRecord)?;
        if path_len > payload.len().saturating_sub(*offset) {
            return Err(Error::CorruptRecord);
        }
        let path = String::from_utf8(payload[*offset..*offset + path_len].to_vec())
            .map_err(|_| Error::CorruptRecord)?;
        *offset += path_len;
        return Ok(path);
    }

    let prefix_len =
        usize::try_from(take_varint(payload, offset)?).map_err(|_| Error::CorruptRecord)?;
    let suffix_len =
        usize::try_from(take_varint(payload, offset)?).map_err(|_| Error::CorruptRecord)?;
    if prefix_len > previous_path.len()
        || !previous_path.is_char_boundary(prefix_len)
        || suffix_len > payload.len().saturating_sub(*offset)
    {
        return Err(Error::CorruptRecord);
    }
    let mut path = Vec::with_capacity(prefix_len + suffix_len);
    path.extend_from_slice(&previous_path.as_bytes()[..prefix_len]);
    path.extend_from_slice(&payload[*offset..*offset + suffix_len]);
    *offset += suffix_len;
    String::from_utf8(path).map_err(|_| Error::CorruptRecord)
}

fn encoded_path_len(path: &str, previous_path: &str, index: usize) -> usize {
    if path_restart(index) {
        return varint_len(path.len() as u64) + path.len();
    }
    let prefix_len = common_prefix_len(previous_path, path);
    let suffix_len = path.len() - prefix_len;
    varint_len(prefix_len as u64) + varint_len(suffix_len as u64) + suffix_len
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrameDescriptor {
    compression_frame_id: u64,
    compression: u8,
    compression_frame_len: u64,
    compressed_len: u64,
    compression_frame_digest: [u8; 32],
    segments: Vec<CompressionFrameSegment>,
}

impl FrameDescriptor {
    fn from_chunk(chunk: &FileChunk) -> Self {
        Self {
            compression_frame_id: chunk.compression_frame_id,
            compression: chunk.compression,
            compression_frame_len: chunk.compression_frame_len,
            compressed_len: chunk.compressed_len,
            compression_frame_digest: chunk.compression_frame_digest,
            segments: chunk.segments.clone(),
        }
    }

    fn matches_chunk(&self, chunk: &FileChunk) -> bool {
        self.compression_frame_id == chunk.compression_frame_id
            && self.compression == chunk.compression
            && self.compression_frame_len == chunk.compression_frame_len
            && self.compressed_len == chunk.compressed_len
            && self.compression_frame_digest == chunk.compression_frame_digest
            && self.segments == chunk.segments
    }
}

fn frame_descriptors(entries: &[&TocEntry]) -> Vec<FrameDescriptor> {
    let mut descriptors = Vec::new();
    for entry in entries {
        for chunk in &entry.chunks {
            if frame_descriptor_index(&descriptors, chunk).is_none() {
                descriptors.push(FrameDescriptor::from_chunk(chunk));
            }
        }
    }
    descriptors
}

fn frame_descriptor_index(descriptors: &[FrameDescriptor], chunk: &FileChunk) -> Option<usize> {
    descriptors
        .iter()
        .position(|descriptor| descriptor.matches_chunk(chunk))
}

fn encode_frame_descriptor(descriptor: &FrameDescriptor, out: &mut Vec<u8>) {
    put_varint(descriptor.compression_frame_id, out);
    put_varint(descriptor.compression as u64, out);
    put_varint(descriptor.compression_frame_len, out);
    put_varint(descriptor.compressed_len, out);
    out.extend_from_slice(&descriptor.compression_frame_digest);
    put_varint(descriptor.segments.len() as u64, out);
    for segment in &descriptor.segments {
        put_varint(segment.page_offset, out);
        put_varint(segment.page_len, out);
        put_varint(segment.object_id, out);
        put_varint(segment.segment_offset, out);
        put_varint(segment.segment_len, out);
    }
}

fn decode_frame_descriptor(payload: &[u8], offset: &mut usize) -> Result<FrameDescriptor> {
    let compression_frame_id = take_varint(payload, offset)?;
    let compression =
        u8::try_from(take_varint(payload, offset)?).map_err(|_| Error::CorruptRecord)?;
    let compression_frame_len = take_varint(payload, offset)?;
    let compressed_len = take_varint(payload, offset)?;
    if *offset + 32 > payload.len() {
        return Err(Error::CorruptRecord);
    }
    let mut compression_frame_digest = [0u8; 32];
    compression_frame_digest.copy_from_slice(&payload[*offset..*offset + 32]);
    *offset += 32;
    let segment_count =
        usize::try_from(take_varint(payload, offset)?).map_err(|_| Error::CorruptRecord)?;
    if segment_count > payload.len().saturating_sub(*offset) {
        return Err(Error::CorruptRecord);
    }
    let mut segments = Vec::with_capacity(segment_count);
    for _ in 0..segment_count {
        let page_offset = take_varint(payload, offset)?;
        let page_len = take_varint(payload, offset)?;
        let object_id = take_varint(payload, offset)?;
        let segment_offset = take_varint(payload, offset)?;
        let segment_len = take_varint(payload, offset)?;
        segments.push(CompressionFrameSegment {
            page_offset,
            page_len,
            object_id,
            segment_offset,
            segment_len,
        });
    }
    Ok(FrameDescriptor {
        compression_frame_id,
        compression,
        compression_frame_len,
        compressed_len,
        compression_frame_digest,
        segments,
    })
}

fn encoded_descriptor_len(descriptor: &FrameDescriptor) -> usize {
    varint_len(descriptor.compression_frame_id)
        + varint_len(descriptor.compression as u64)
        + varint_len(descriptor.compression_frame_len)
        + varint_len(descriptor.compressed_len)
        + 32
        + varint_len(descriptor.segments.len() as u64)
        + descriptor
            .segments
            .iter()
            .map(encoded_segment_len)
            .sum::<usize>()
}

fn encoded_chunk_len(
    entry: &TocEntry,
    chunk: &FileChunk,
    descriptors: &[FrameDescriptor],
) -> usize {
    let stored_path_len = if chunk.stored_path == entry.path.as_str() {
        0
    } else {
        chunk.stored_path.len()
    };
    varint_len(stored_path_len as u64)
        + stored_path_len
        + varint_len(chunk.file_offset)
        + varint_len(chunk.len)
        + varint_len(chunk.compression_frame_offset)
        + varint_len(frame_descriptor_index(descriptors, chunk).unwrap_or(0) as u64)
}

fn encoded_segment_len(segment: &CompressionFrameSegment) -> usize {
    varint_len(segment.page_offset)
        + varint_len(segment.page_len)
        + varint_len(segment.object_id)
        + varint_len(segment.segment_offset)
        + varint_len(segment.segment_len)
}

fn path_restart(index: usize) -> bool {
    index % PATH_RESTART_INTERVAL == 0
}

fn common_prefix_len(previous: &str, current: &str) -> usize {
    let mut len = previous
        .as_bytes()
        .iter()
        .zip(current.as_bytes())
        .take_while(|(left, right)| left == right)
        .count();
    while len > 0 && !current.is_char_boundary(len) {
        len -= 1;
    }
    len
}

fn default_permissions(node_kind: NodeKind) -> u32 {
    match node_kind {
        NodeKind::File => DEFAULT_FILE_PERMISSIONS,
        NodeKind::Symlink => DEFAULT_SYMLINK_PERMISSIONS,
    }
}

fn put_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn take_varint(payload: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        if *cursor >= payload.len() {
            return Err(Error::CorruptRecord);
        }
        let byte = payload[*cursor];
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(Error::CorruptRecord)
}

pub(crate) fn varint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        len += 1;
        value >>= 7;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn decoded_toc_rejects_tampered_host_paths() {
        let mut toc_entries = BTreeMap::new();
        let invalid_path = LockboxPath::from_unchecked_for_test("/C:/Users/target.txt");
        toc_entries.insert(
            invalid_path.clone(),
            TocEntry {
                path: invalid_path,
                len: 1,
                record_offset: 64,
                record_len: 64,
                record_object_id: 1,
                deleted: false,
                node_kind: NodeKind::File,
                permissions: DEFAULT_FILE_PERMISSIONS,
                chunks: Vec::new(),
            },
        );
        let payload = encode_toc(&toc_entries);
        assert!(matches!(decode_toc(&payload), Err(Error::InvalidPath(_))));
    }

    #[test]
    fn decoded_toc_rejects_impossible_entry_count_before_allocating() {
        let payload = u64::MAX.to_le_bytes();

        assert!(matches!(
            decode_toc_entries(&payload),
            Err(Error::CorruptRecord)
        ));
    }

    #[test]
    fn decoded_toc_rejects_symlink_without_object_reference() {
        let payload = encoded_symlink_entry("/links/current", 0, 0, 0);

        assert!(matches!(
            decode_toc_entries(&payload),
            Err(Error::CorruptRecord)
        ));
    }

    #[test]
    fn toc_entries_round_trip_front_coded_paths_with_restarts() {
        let entries = (0..260)
            .map(|i| TocEntry {
                path: LockboxPath::new(format!("/docs/chapter-{i:03}/index.txt")).unwrap(),
                len: 25_600,
                record_offset: 96 + i * 1024,
                record_len: 1024,
                record_object_id: i + 1,
                deleted: false,
                node_kind: NodeKind::File,
                permissions: DEFAULT_FILE_PERMISSIONS,
                chunks: Vec::new(),
            })
            .collect::<Vec<_>>();

        let payload = encode_toc_entries(entries.iter());
        assert_eq!(payload.len(), encoded_toc_entries_len(&entries));
        let decoded = decode_toc_entries(&payload).unwrap();

        assert_eq!(decoded.len(), entries.len());
        for (decoded, expected) in decoded.iter().zip(entries.iter()) {
            assert_eq!(decoded.path, expected.path);
            assert_eq!(decoded.len, expected.len);
            assert_eq!(decoded.record_offset, expected.record_offset);
            assert_eq!(decoded.record_len, expected.record_len);
            assert_eq!(decoded.record_object_id, expected.record_object_id);
        }
    }

    #[test]
    fn front_coding_handles_unicode_boundaries() {
        let entries = [
            TocEntry {
                path: LockboxPath::new("/docs/cafe\u{301}/a.txt").unwrap(),
                len: 1,
                record_offset: 64,
                record_len: 64,
                record_object_id: 1,
                deleted: false,
                node_kind: NodeKind::File,
                permissions: DEFAULT_FILE_PERMISSIONS,
                chunks: Vec::new(),
            },
            TocEntry {
                path: LockboxPath::new("/docs/cafe\u{301}/b.txt").unwrap(),
                len: 1,
                record_offset: 64,
                record_len: 64,
                record_object_id: 1,
                deleted: false,
                node_kind: NodeKind::File,
                permissions: DEFAULT_FILE_PERMISSIONS,
                chunks: Vec::new(),
            },
        ];

        let payload = encode_toc_entries(entries.iter());
        let decoded = decode_toc_entries(&payload).unwrap();

        assert_eq!(decoded[0].path, entries[0].path);
        assert_eq!(decoded[1].path, entries[1].path);
    }

    #[test]
    fn toc_entries_share_frame_descriptors_across_chunks() {
        let entries = (0..4)
            .map(|i| TocEntry {
                path: LockboxPath::new(format!("/tree/file-{i}.bin")).unwrap(),
                len: 128,
                record_offset: 4096,
                record_len: 4096,
                record_object_id: 10,
                deleted: false,
                node_kind: NodeKind::File,
                permissions: DEFAULT_FILE_PERMISSIONS,
                chunks: vec![shared_frame_chunk(i)],
            })
            .collect::<Vec<_>>();

        let payload = encode_toc_entries(entries.iter());
        assert_eq!(payload.len(), encoded_toc_entries_len(&entries));
        let decoded = decode_toc_entries(&payload).unwrap();

        assert_eq!(decoded.len(), entries.len());
        for (decoded, expected) in decoded.iter().zip(entries.iter()) {
            assert_eq!(decoded.path, expected.path);
            assert_eq!(decoded.len, expected.len);
            assert_eq!(decoded.chunks, expected.chunks);
        }
        assert!(
            payload.len()
                < entries
                    .iter()
                    .map(|entry| 64 + entry.path.len())
                    .sum::<usize>()
        );
    }

    #[test]
    fn toc_decode_rejects_invalid_frame_descriptor_index() {
        let entry = TocEntry {
            path: LockboxPath::new("/tree/file.bin").unwrap(),
            len: 128,
            record_offset: 4096,
            record_len: 4096,
            record_object_id: 10,
            deleted: false,
            node_kind: NodeKind::File,
            permissions: DEFAULT_FILE_PERMISSIONS,
            chunks: vec![shared_frame_chunk(0)],
        };
        let mut payload = encode_toc_entries([&entry]);
        let last = payload.last_mut().unwrap();
        *last = last.saturating_add(1);

        assert!(matches!(
            decode_toc_entries(&payload),
            Err(Error::CorruptRecord)
        ));
    }

    fn encoded_symlink_entry(
        path: &str,
        record_offset: u64,
        record_len: u64,
        record_object_id: u64,
    ) -> Vec<u8> {
        encode_toc_entries([&TocEntry {
            path: LockboxPath::new(path).unwrap(),
            len: 0,
            record_offset,
            record_len,
            record_object_id,
            deleted: false,
            node_kind: NodeKind::Symlink,
            permissions: DEFAULT_SYMLINK_PERMISSIONS,
            chunks: Vec::new(),
        }])
    }

    fn shared_frame_chunk(index: u64) -> FileChunk {
        FileChunk {
            stored_path: LockboxPath::new(format!("/tree/file-{index}.bin")).unwrap(),
            file_offset: 0,
            len: 128,
            compression_frame_offset: index * 128,
            compression_frame_len: 512,
            compressed_len: 42,
            compression: 1,
            compression_frame_id: 7,
            compression_frame_digest: [9; 32],
            segments: vec![CompressionFrameSegment {
                page_offset: 4096,
                page_len: 4096,
                object_id: 10,
                segment_offset: 0,
                segment_len: 42,
            }],
        }
    }
}
