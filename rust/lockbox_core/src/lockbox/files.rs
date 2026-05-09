use std::io::{Cursor, Read, Write};

use super::Lockbox;
use crate::constants::{DEFAULT_FILE_PERMISSIONS, DEFAULT_MAX_SEGMENT_BODY_BYTES};
use crate::file_chunk::{FileChunk, PendingFileChunk};
use crate::format::{decode_file_segment_payload, encode_file_segment_payload};
use crate::logical_path::{canonicalize_api_path as canonicalize_path, LogicalPath};
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::record::RecordKind;
use crate::security::validate_permissions;
use crate::{Error, Result};

const SMALL_FILE_PACKING_LIMIT: usize = 1024 * 1024;

impl Lockbox {
    pub fn put_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.put_file_with_permissions(path, data, DEFAULT_FILE_PERMISSIONS)
    }

    pub fn put_file_with_permissions(
        &mut self,
        path: &str,
        data: &[u8],
        permissions: u32,
    ) -> Result<()> {
        if data.len() <= SMALL_FILE_PACKING_LIMIT {
            return self.stage_small_file(path, data, permissions);
        }
        self.put_file_from_reader_with_permissions(path, Cursor::new(data), permissions)
    }

    pub fn put_file_from_reader(&mut self, path: &str, reader: impl Read) -> Result<()> {
        self.put_file_from_reader_with_permissions(path, reader, DEFAULT_FILE_PERMISSIONS)
    }

    pub fn put_file_from_reader_with_permissions(
        &mut self,
        path: &str,
        mut reader: impl Read,
        permissions: u32,
    ) -> Result<()> {
        let path = canonicalize_path(path, false)?;
        let permissions = validate_permissions(permissions)?;
        self.pending_small_files.remove(&path);
        if let Some(old) = self.manifest.get(path.as_str()).cloned() {
            self.free_entry_slots(old);
        }

        let mut chunks = Vec::new();
        let mut file_offset = 0u64;
        let mut buffer = vec![0; DEFAULT_MAX_SEGMENT_BODY_BYTES];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|err| Error::Io(err.to_string()))?;
            if read == 0 {
                if file_offset == 0 {
                    self.write_file_chunk(&path, permissions, 0, &[], &mut chunks)?;
                }
                break;
            }
            self.write_file_chunk(
                &path,
                permissions,
                file_offset,
                &buffer[..read],
                &mut chunks,
            )?;
            file_offset += read as u64;
        }

        let dirty_path = path.clone();
        let entry = ManifestEntry {
            path,
            len: file_offset,
            record_offset: chunks.first().map(|chunk| chunk.record_offset).unwrap_or(0),
            record_len: chunks.first().map(|chunk| chunk.record_len).unwrap_or(0),
            deleted: false,
            node_kind: NodeKind::File,
            permissions,
            symlink_target: None,
            chunks,
        };
        self.add_entry_record_refs(&entry);
        self.manifest
            .insert(LogicalPath::from_canonical(entry.path.clone()), entry);
        self.mark_toc_dirty(&dirty_path);
        self.needs_packing = true;
        Ok(())
    }

    pub fn get_file(&self, path: &str) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.write_file_to(path, &mut out)?;
        Ok(out)
    }

    pub fn write_file_to(&self, path: &str, mut writer: impl Write) -> Result<()> {
        let path = canonicalize_path(path, false)?;
        let entry = self
            .manifest
            .get(path.as_str())
            .filter(|entry| !entry.deleted && entry.node_kind == NodeKind::File)
            .ok_or_else(|| Error::NotFound(path.clone()))?;

        if let Some(pending) = self.pending_small_files.get(path.as_str()) {
            writer
                .write_all(&pending.data)
                .map_err(|err| Error::Io(err.to_string()))?;
            return Ok(());
        }

        if entry.chunks.is_empty() {
            return Err(Error::CorruptRecord);
        }

        let mut chunks = entry.chunks.clone();
        chunks.sort_by_key(|chunk| chunk.file_offset);
        for chunk in chunks {
            let record = self.read_record(chunk.record_offset)?;
            let decoded = decode_file_segment_payload(&record.payload)?;
            let Some(decoded_chunk) = decoded
                .into_iter()
                .find(|item| item.path == path && item.file_offset == chunk.file_offset)
            else {
                return Err(Error::CorruptRecord);
            };
            writer
                .write_all(&decoded_chunk.data)
                .map_err(|err| Error::Io(err.to_string()))?;
        }
        Ok(())
    }

    pub fn permissions(&self, path: &str) -> Option<u32> {
        let path = canonicalize_path(path, false).ok()?;
        self.manifest
            .get(path.as_str())
            .filter(|entry| !entry.deleted)
            .map(|entry| entry.permissions)
    }

    pub fn read_file_range(&self, path: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        let path = canonicalize_path(path, false)?;
        let entry = self
            .manifest
            .get(path.as_str())
            .filter(|entry| !entry.deleted && entry.node_kind == NodeKind::File)
            .ok_or_else(|| Error::NotFound(path.clone()))?;
        if len == 0 || offset >= entry.len {
            return Ok(Vec::new());
        }
        let wanted_end = offset.saturating_add(len).min(entry.len);

        if let Some(pending) = self.pending_small_files.get(path.as_str()) {
            let start = offset.min(pending.data.len() as u64) as usize;
            let end = wanted_end.min(pending.data.len() as u64) as usize;
            return Ok(pending.data[start..end].to_vec());
        }

        if entry.chunks.is_empty() {
            return Err(Error::CorruptRecord);
        }

        let mut out = Vec::with_capacity((wanted_end - offset) as usize);
        let mut chunks = entry.chunks.clone();
        chunks.sort_by_key(|chunk| chunk.file_offset);
        for chunk in chunks {
            let chunk_start = chunk.file_offset;
            let chunk_end = chunk.file_offset.saturating_add(chunk.len);
            if chunk_end <= offset || chunk_start >= wanted_end {
                continue;
            }

            let record = self.read_record(chunk.record_offset)?;
            let decoded = decode_file_segment_payload(&record.payload)?;
            let Some(decoded_chunk) = decoded
                .into_iter()
                .find(|item| item.path == path && item.file_offset == chunk.file_offset)
            else {
                return Err(Error::CorruptRecord);
            };

            let copy_start = offset.max(chunk_start) - chunk_start;
            let copy_end = wanted_end.min(chunk_end) - chunk_start;
            out.extend_from_slice(&decoded_chunk.data[copy_start as usize..copy_end as usize]);
        }
        Ok(out)
    }

    fn write_file_chunk(
        &mut self,
        path: &str,
        permissions: u32,
        file_offset: u64,
        data: &[u8],
        chunks: &mut Vec<FileChunk>,
    ) -> Result<()> {
        self.sequence += 1;
        let pending = PendingFileChunk {
            path: path.to_string(),
            permissions,
            total_len: 0,
            file_offset,
            data: data.to_vec(),
        };
        let segment_inner_offset = file_segment_inner_offsets(std::slice::from_ref(&pending))
            .into_iter()
            .next()
            .ok_or(Error::CorruptRecord)?;
        let payload = encode_file_segment_payload(&[pending]);
        let record_offset =
            self.write_object_page(RecordKind::FileSegment, self.sequence, payload)?;
        let record_len = crate::segment_page::DEFAULT_SEGMENT_PAGE_BYTES as u64;
        chunks.push(FileChunk {
            record_offset,
            record_len,
            file_offset,
            len: data.len() as u64,
            segment_inner_offset,
            segment_inner_len: data.len() as u64,
        });
        Ok(())
    }

    fn stage_small_file(&mut self, path: &str, data: &[u8], permissions: u32) -> Result<()> {
        let path = canonicalize_path(path, false)?;
        let permissions = validate_permissions(permissions)?;
        if let Some(old) = self.manifest.get(path.as_str()).cloned() {
            self.free_entry_slots(old);
        }

        self.pending_small_files.insert(
            path.clone(),
            PendingFileChunk {
                path: path.clone(),
                permissions,
                total_len: data.len() as u64,
                file_offset: 0,
                data: data.to_vec(),
            },
        );
        let dirty_path = path.clone();
        self.manifest.insert(
            LogicalPath::from_canonical(path.clone()),
            ManifestEntry {
                path,
                len: data.len() as u64,
                record_offset: 0,
                record_len: 0,
                deleted: false,
                node_kind: NodeKind::File,
                permissions,
                symlink_target: None,
                chunks: Vec::new(),
            },
        );
        self.mark_toc_dirty(&dirty_path);
        Ok(())
    }

    pub(crate) fn flush_pending_small_files(&mut self) -> Result<()> {
        if self.pending_small_files.is_empty() {
            return Ok(());
        }

        let pending = std::mem::take(&mut self.pending_small_files);
        let mut batch = Vec::new();
        let mut batch_size = 0usize;
        for chunk in pending.into_values() {
            let entry_size = 2 + chunk.path.len() + 28 + chunk.data.len();
            if !batch.is_empty() && batch_size + entry_size > DEFAULT_MAX_SEGMENT_BODY_BYTES {
                self.write_packed_file_segment(&batch)?;
                batch.clear();
                batch_size = 0;
            }
            batch_size += entry_size;
            batch.push(chunk);
        }
        if !batch.is_empty() {
            self.write_packed_file_segment(&batch)?;
        }
        Ok(())
    }

    pub(crate) fn pack_small_file_segments(&mut self) -> Result<()> {
        let mut candidates = Vec::new();
        for entry in self.manifest.values() {
            if entry.deleted || entry.node_kind != NodeKind::File || entry.len > 1024 * 1024 {
                continue;
            }
            let data = self.get_file(&entry.path)?;
            candidates.push((entry.path.clone(), entry.permissions, data, entry.clone()));
        }

        if candidates.len() < 10 {
            return Ok(());
        }

        for (_, _, _, old) in &candidates {
            self.free_entry_slots(old.clone());
        }

        let mut batch = Vec::new();
        let mut batch_size = 0usize;
        for (path, permissions, data, _) in candidates {
            let entry_size = 2 + path.len() + 28 + data.len();
            if !batch.is_empty() && batch_size + entry_size > DEFAULT_MAX_SEGMENT_BODY_BYTES {
                self.write_packed_file_segment(&batch)?;
                batch.clear();
                batch_size = 0;
            }
            batch_size += entry_size;
            batch.push(PendingFileChunk {
                path,
                permissions,
                total_len: data.len() as u64,
                file_offset: 0,
                data,
            });
        }
        if !batch.is_empty() {
            self.write_packed_file_segment(&batch)?;
        }
        Ok(())
    }

    fn write_packed_file_segment(&mut self, chunks: &[PendingFileChunk]) -> Result<()> {
        self.sequence += 1;
        let payload = encode_file_segment_payload(chunks);
        let inner_offsets = file_segment_inner_offsets(chunks);
        let record_offset =
            self.write_object_page(RecordKind::FileSegment, self.sequence, payload)?;
        let record_len = crate::segment_page::DEFAULT_SEGMENT_PAGE_BYTES as u64;
        let mut dirty_paths = Vec::new();
        let mut updated_entries = Vec::new();
        for (chunk, segment_inner_offset) in chunks.iter().zip(inner_offsets) {
            if let Some(entry) = self.manifest.get_mut(chunk.path.as_str()) {
                entry.record_offset = record_offset;
                entry.record_len = record_len;
                entry.len = chunk.total_len;
                entry.permissions = chunk.permissions;
                entry.chunks = vec![FileChunk {
                    record_offset,
                    record_len,
                    file_offset: chunk.file_offset,
                    len: chunk.data.len() as u64,
                    segment_inner_offset,
                    segment_inner_len: chunk.data.len() as u64,
                }];
                dirty_paths.push(entry.path.clone());
                updated_entries.push(entry.clone());
            }
        }
        for entry in &updated_entries {
            self.add_entry_record_refs(entry);
        }
        self.mark_toc_dirty_paths(dirty_paths.iter().map(String::as_str));
        Ok(())
    }
}

fn file_segment_inner_offsets(chunks: &[PendingFileChunk]) -> Vec<u64> {
    let mut offsets = Vec::with_capacity(chunks.len());
    let mut offset = 4u64;
    for chunk in chunks {
        offset += 2 + chunk.path.len() as u64 + 4 + 8 + 8 + 8;
        offsets.push(offset);
        offset += chunk.data.len() as u64;
    }
    offsets
}
