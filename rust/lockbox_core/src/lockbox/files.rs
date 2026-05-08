use std::io::{Cursor, Read, Write};

use super::Lockbox;
use crate::constants::{DEFAULT_FILE_PERMISSIONS, DEFAULT_MAX_SEGMENT_BODY_BYTES};
use crate::file_chunk::{FileChunk, PendingFileChunk};
use crate::format::{
    decode_file_payload, decode_file_segment_payload, encode_file_segment_payload, encode_record,
    read_record,
};
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::record::RecordKind;
use crate::security::{canonicalize_path, validate_permissions};
use crate::{Error, Result};

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
        if let Some(old) = self.manifest.get(&path).cloned() {
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

        self.manifest.insert(
            path.clone(),
            ManifestEntry {
                path,
                len: file_offset,
                record_offset: chunks.first().map(|chunk| chunk.record_offset).unwrap_or(0),
                record_len: chunks.first().map(|chunk| chunk.record_len).unwrap_or(0),
                deleted: false,
                node_kind: NodeKind::File,
                permissions,
                symlink_target: None,
                chunks,
            },
        );
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
            .get(&path)
            .filter(|entry| !entry.deleted && entry.node_kind == NodeKind::File)
            .ok_or_else(|| Error::NotFound(path.clone()))?;

        if entry.chunks.is_empty() {
            let record = read_record(&self.bytes, entry.record_offset, self.key.expose())?;
            let (_, _, data) = decode_file_payload(&record.payload)?;
            writer
                .write_all(&data)
                .map_err(|err| Error::Io(err.to_string()))?;
            return Ok(());
        }

        let mut chunks = entry.chunks.clone();
        chunks.sort_by_key(|chunk| chunk.file_offset);
        for chunk in chunks {
            let record = read_record(&self.bytes, chunk.record_offset, self.key.expose())?;
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
            .get(&path)
            .filter(|entry| !entry.deleted)
            .map(|entry| entry.permissions)
    }

    pub fn read_file_range(&self, path: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        let path = canonicalize_path(path, false)?;
        let entry = self
            .manifest
            .get(&path)
            .filter(|entry| !entry.deleted && entry.node_kind == NodeKind::File)
            .ok_or_else(|| Error::NotFound(path.clone()))?;
        if len == 0 || offset >= entry.len {
            return Ok(Vec::new());
        }
        let wanted_end = offset.saturating_add(len).min(entry.len);

        if entry.chunks.is_empty() {
            let record = read_record(&self.bytes, entry.record_offset, self.key.expose())?;
            let (_, _, data) = decode_file_payload(&record.payload)?;
            let start = offset.min(data.len() as u64) as usize;
            let end = wanted_end.min(data.len() as u64) as usize;
            return Ok(data[start..end].to_vec());
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

            let record = read_record(&self.bytes, chunk.record_offset, self.key.expose())?;
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
        let payload = encode_file_segment_payload(&[pending]);
        let record = encode_record(
            RecordKind::FileSegment,
            self.sequence,
            &payload,
            self.key.expose(),
        );
        let record_len = record.len() as u64;
        let record_offset = self.write_record(record);
        let decoded = read_record(&self.bytes, record_offset, self.key.expose())
            .and_then(|record| decode_file_segment_payload(&record.payload))?;
        let Some(decoded_chunk) = decoded.into_iter().next() else {
            return Err(Error::CorruptRecord);
        };
        chunks.push(FileChunk {
            record_offset,
            record_len,
            file_offset,
            len: data.len() as u64,
            segment_inner_offset: decoded_chunk.segment_inner_offset,
            segment_inner_len: data.len() as u64,
        });
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
        let record = encode_record(
            RecordKind::FileSegment,
            self.sequence,
            &payload,
            self.key.expose(),
        );
        let record_len = record.len() as u64;
        let record_offset = self.write_record(record);
        let decoded = read_record(&self.bytes, record_offset, self.key.expose())
            .and_then(|record| decode_file_segment_payload(&record.payload))?;
        for decoded_chunk in decoded {
            if let Some(entry) = self.manifest.get_mut(&decoded_chunk.path) {
                entry.record_offset = record_offset;
                entry.record_len = record_len;
                entry.len = decoded_chunk.total_len;
                entry.permissions = decoded_chunk.permissions;
                entry.chunks = vec![FileChunk {
                    record_offset,
                    record_len,
                    file_offset: decoded_chunk.file_offset,
                    len: decoded_chunk.data.len() as u64,
                    segment_inner_offset: decoded_chunk.segment_inner_offset,
                    segment_inner_len: decoded_chunk.data.len() as u64,
                }];
            }
        }
        Ok(())
    }
}
