use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::sync::Arc;

use super::Lockbox;
use crate::compression::{decode_file_frame, encode_file_frame};
use crate::constants::{DEFAULT_FILE_PERMISSIONS, DEFAULT_MAX_PAGE_BODY_BYTES};
use crate::file_chunk::{FileChunk, FileFragment, PendingFileChunk};
use crate::format::{decode_file_fragment_payload, encode_file_fragment_payload};
use crate::logical_path::{canonicalize_api_path as canonicalize_path, LogicalPath};
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::page::{
    encoded_object_len, uncompressed_objects_fit, PageObject, PageObjectKind, DEFAULT_PAGE_BYTES,
};
use crate::security::validate_permissions;
use crate::{Error, Result};

const SMALL_FILE_PACKING_LIMIT: usize = 1024 * 1024;
const FILE_FRAME_BYTES: usize = 1020 * 1024;
const MAX_FRAGMENT_BYTES: usize = DEFAULT_MAX_PAGE_BODY_BYTES - 64 * 1024;

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

    pub fn add_file_from_reader(&mut self, path: &str, reader: impl Read) -> Result<()> {
        self.put_file_from_reader(path, reader)
    }

    pub fn add_file(&mut self, source: impl AsRef<Path>, destination: &str) -> Result<()> {
        let file = std::fs::File::open(source.as_ref())
            .map_err(|err| Error::Io(format!("open {}: {err}", source.as_ref().display())))?;
        self.add_file_from_reader(destination, file)
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
            self.free_entry_slots(old)?;
        }

        let mut chunks = Vec::new();
        let mut file_offset = 0u64;
        let mut writer = FilePageWriter::new(self);
        let skip_compression = likely_incompressible_path(&path);
        let mut buffer = vec![0; FILE_FRAME_BYTES];
        loop {
            let read = read_next_chunk(&mut reader, &mut buffer)?;
            if read == 0 {
                if file_offset == 0 {
                    writer.write_frame(
                        FileFrameWrite {
                            path: &path,
                            permissions,
                            total_len: 0,
                            file_offset: 0,
                            data: &[],
                            skip_compression,
                        },
                        &mut chunks,
                    )?;
                }
                break;
            }
            writer.write_frame(
                FileFrameWrite {
                    path: &path,
                    permissions,
                    total_len: 0,
                    file_offset,
                    data: &buffer[..read],
                    skip_compression,
                },
                &mut chunks,
            )?;
            file_offset += read as u64;
        }
        writer.finish(&mut chunks)?;

        let dirty_path = path.clone();
        let entry = ManifestEntry {
            path,
            len: file_offset,
            record_offset: chunks
                .first()
                .and_then(|chunk| chunk.fragments.first())
                .map(|fragment| fragment.page_offset)
                .unwrap_or(0),
            record_len: DEFAULT_PAGE_BYTES as u64,
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
        self.extract_file_to_writer(path, &mut out)?;
        Ok(out)
    }

    pub fn write_file_to(&self, path: &str, mut writer: impl Write) -> Result<()> {
        self.extract_file_to_writer(path, &mut writer)
    }

    pub fn extract_file_to_writer(&self, path: &str, mut writer: impl Write) -> Result<()> {
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
            let decoded_chunk = self.read_file_chunk_frame(&entry.path, entry.len, &chunk)?;
            writer
                .write_all(&decoded_chunk)
                .map_err(|err| Error::Io(err.to_string()))?;
        }
        Ok(())
    }

    pub fn extract_file_to(&self, source: &str, destination: impl AsRef<Path>) -> Result<()> {
        let mut file = std::fs::File::create(destination.as_ref()).map_err(|err| {
            Error::Io(format!("create {}: {err}", destination.as_ref().display()))
        })?;
        self.extract_file_to_writer(source, &mut file)
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

            let decoded_chunk = self.read_file_chunk_frame(&entry.path, entry.len, &chunk)?;

            let copy_start = offset.max(chunk_start) - chunk_start;
            let copy_end = wanted_end.min(chunk_end) - chunk_start;
            out.extend_from_slice(&decoded_chunk[copy_start as usize..copy_end as usize]);
        }
        Ok(out)
    }

    pub(crate) fn read_file_chunk_frame(
        &self,
        expected_path: &str,
        expected_total_len: u64,
        chunk: &FileChunk,
    ) -> Result<Vec<u8>> {
        let mut stored = vec![0u8; chunk.compressed_len as usize];
        for fragment in &chunk.fragments {
            let object = self.read_page_object(fragment.page_offset, fragment.object_id)?;
            let decoded = decode_file_fragment_payload(&object.payload)?;
            if decoded.path != expected_path
                || (decoded.total_len != 0 && decoded.total_len != expected_total_len)
                || decoded.frame_id != chunk.frame_id
                || decoded.file_offset != chunk.file_offset
                || decoded.len != chunk.len
                || decoded.compressed_len != chunk.compressed_len
                || decoded.compression != chunk.compression
                || decoded.fragment_offset != fragment.fragment_offset
                || decoded.data.len() as u64 != fragment.fragment_len
            {
                return Err(Error::CorruptRecord);
            }
            let start =
                usize::try_from(fragment.fragment_offset).map_err(|_| Error::CorruptRecord)?;
            let end = start
                .checked_add(decoded.data.len())
                .ok_or(Error::CorruptRecord)?;
            if end > stored.len() {
                return Err(Error::CorruptRecord);
            }
            stored[start..end].copy_from_slice(&decoded.data);
        }
        decode_file_frame(chunk.compression, &stored, chunk.len)
    }

    fn stage_small_file(&mut self, path: &str, data: &[u8], permissions: u32) -> Result<()> {
        let path = canonicalize_path(path, false)?;
        let permissions = validate_permissions(permissions)?;
        if let Some(old) = self.manifest.get(path.as_str()).cloned() {
            self.free_entry_slots(old)?;
        }

        self.pending_small_files.insert(
            path.clone(),
            PendingFileChunk {
                path: path.clone(),
                permissions,
                total_len: data.len() as u64,
                file_offset: 0,
                data: Arc::from(data),
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
        let mut writer = FilePageWriter::new(self);
        let mut all_chunks = Vec::new();
        let mut updates = Vec::new();
        let mut dirty_paths = Vec::new();
        for chunk in pending.into_values() {
            let start = all_chunks.len();
            writer.write_frame(
                FileFrameWrite {
                    path: &chunk.path,
                    permissions: chunk.permissions,
                    total_len: chunk.total_len,
                    file_offset: 0,
                    data: &chunk.data,
                    skip_compression: likely_incompressible_path(&chunk.path),
                },
                &mut all_chunks,
            )?;
            updates.push((chunk.path, chunk.permissions, chunk.total_len, start));
        }
        writer.finish(&mut all_chunks)?;
        for (path, permissions, total_len, start) in updates {
            let chunks = all_chunks[start..start + 1].to_vec();
            if let Some(entry) = writer.lockbox.manifest.get_mut(path.as_str()) {
                entry.record_offset = chunks
                    .first()
                    .and_then(|chunk| chunk.fragments.first())
                    .map(|fragment| fragment.page_offset)
                    .unwrap_or(0);
                entry.record_len = DEFAULT_PAGE_BYTES as u64;
                entry.len = total_len;
                entry.permissions = permissions;
                entry.chunks = chunks;
                dirty_paths.push(entry.path.clone());
                let entry = entry.clone();
                writer.lockbox.add_entry_record_refs(&entry);
            }
        }
        writer
            .lockbox
            .mark_toc_dirty_paths(dirty_paths.iter().map(String::as_str));
        Ok(())
    }

    pub(crate) fn pack_small_file_pages(&mut self) -> Result<()> {
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
            self.free_entry_slots(old.clone())?;
        }

        let mut writer = FilePageWriter::new(self);
        let mut all_chunks = Vec::new();
        let mut updates = Vec::new();
        let mut dirty_paths = Vec::new();
        for (path, permissions, data, _) in candidates {
            let start = all_chunks.len();
            let len = data.len() as u64;
            writer.write_frame(
                FileFrameWrite {
                    path: &path,
                    permissions,
                    total_len: len,
                    file_offset: 0,
                    data: &data,
                    skip_compression: likely_incompressible_path(&path),
                },
                &mut all_chunks,
            )?;
            updates.push((path, permissions, len, start));
        }
        writer.finish(&mut all_chunks)?;
        for (path, permissions, len, start) in updates {
            let chunks = all_chunks[start..start + 1].to_vec();
            if let Some(entry) = writer.lockbox.manifest.get_mut(path.as_str()) {
                entry.record_offset = chunks
                    .first()
                    .and_then(|chunk| chunk.fragments.first())
                    .map(|fragment| fragment.page_offset)
                    .unwrap_or(0);
                entry.record_len = DEFAULT_PAGE_BYTES as u64;
                entry.len = len;
                entry.permissions = permissions;
                entry.chunks = chunks;
                dirty_paths.push(entry.path.clone());
                let entry = entry.clone();
                writer.lockbox.add_entry_record_refs(&entry);
            }
        }
        writer
            .lockbox
            .mark_toc_dirty_paths(dirty_paths.iter().map(String::as_str));
        Ok(())
    }
}

fn read_next_chunk(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize> {
    let mut read_total = 0usize;
    while read_total < buffer.len() {
        let read = reader
            .read(&mut buffer[read_total..])
            .map_err(|err| Error::Io(err.to_string()))?;
        if read == 0 {
            break;
        }
        read_total += read;
    }
    Ok(read_total)
}

fn likely_incompressible_path(path: &str) -> bool {
    let Some(extension) = path.rsplit_once('.').map(|(_, extension)| extension) else {
        return false;
    };
    INCOMPRESSIBLE_EXTENSIONS
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
}

const INCOMPRESSIBLE_EXTENSIONS: &[&str] = &[
    "7z", "apk", "avi", "br", "bz2", "cab", "cr2", "deb", "dmg", "docx", "flac", "gif", "gz",
    "heic", "iso", "jar", "jpeg", "jpg", "m4a", "mkv", "mov", "mp3", "mp4", "ogg", "pdf", "png",
    "pptx", "rar", "rpm", "webm", "webp", "xlsx", "xz", "zip", "zst",
];

struct PendingPageObject {
    chunk_index: usize,
    fragment_offset: u64,
    fragment_len: u64,
    object: PageObject,
}

struct FilePageWriter<'a> {
    lockbox: &'a mut Lockbox,
    pending: Vec<PendingPageObject>,
    pending_object_stream_len: usize,
}

#[derive(Clone, Copy)]
struct FileFrameWrite<'a> {
    path: &'a str,
    permissions: u32,
    total_len: u64,
    file_offset: u64,
    data: &'a [u8],
    skip_compression: bool,
}

impl<'a> FilePageWriter<'a> {
    fn new(lockbox: &'a mut Lockbox) -> Self {
        Self {
            lockbox,
            pending: Vec::new(),
            pending_object_stream_len: 4,
        }
    }

    fn write_frame(
        &mut self,
        frame: FileFrameWrite<'_>,
        chunks: &mut Vec<FileChunk>,
    ) -> Result<()> {
        let (compression, stored) = encode_file_frame(frame.data, frame.skip_compression);
        self.lockbox.sequence += 1;
        let frame_id = self.lockbox.sequence;
        let chunk_index = chunks.len();
        chunks.push(FileChunk {
            file_offset: frame.file_offset,
            len: frame.data.len() as u64,
            compressed_len: stored.len() as u64,
            compression,
            frame_id,
            fragments: Vec::new(),
        });

        if stored.is_empty() {
            self.add_fragment(
                frame.path,
                frame.permissions,
                frame.total_len,
                frame.file_offset,
                frame.data.len() as u64,
                compression,
                frame_id,
                0,
                stored.len() as u64,
                chunk_index,
                &[],
                chunks,
            )?;
            return Ok(());
        }

        let mut offset = 0usize;
        while offset < stored.len() {
            let end = (offset + MAX_FRAGMENT_BYTES).min(stored.len());
            self.add_fragment(
                frame.path,
                frame.permissions,
                frame.total_len,
                frame.file_offset,
                frame.data.len() as u64,
                compression,
                frame_id,
                offset as u64,
                stored.len() as u64,
                chunk_index,
                &stored[offset..end],
                chunks,
            )?;
            offset = end;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn add_fragment(
        &mut self,
        path: &str,
        permissions: u32,
        total_len: u64,
        file_offset: u64,
        frame_len: u64,
        compression: u8,
        frame_id: u64,
        fragment_offset: u64,
        compressed_len: u64,
        chunk_index: usize,
        fragment: &[u8],
        chunks: &mut [FileChunk],
    ) -> Result<()> {
        self.lockbox.sequence += 1;
        let object_id = self.lockbox.sequence;
        let payload = encode_file_fragment_payload(
            &PendingFileChunk {
                path: path.to_string(),
                permissions,
                total_len,
                file_offset,
                data: Arc::from(fragment),
            },
            compression,
            frame_id,
            frame_len,
            compressed_len,
            fragment_offset,
        );
        let object = PageObject {
            kind: PageObjectKind::FileData,
            id: object_id,
            payload,
        };
        let pending = PendingPageObject {
            chunk_index,
            fragment_offset,
            fragment_len: fragment.len() as u64,
            object,
        };

        let encoded_len = encoded_object_len(&pending.object)?;
        if !self.pending.is_empty() && !self.fits_with(encoded_len)? {
            self.flush(chunks)?;
        }
        if !self.fits_with(encoded_len)? {
            return Err(Error::SecurityLimitExceeded(
                "file fragment does not fit in a page".to_string(),
            ));
        }
        self.pending_object_stream_len = self
            .pending_object_stream_len
            .checked_add(encoded_len)
            .ok_or_else(|| Error::SecurityLimitExceeded("page is too large".to_string()))?;
        self.pending.push(pending);
        Ok(())
    }

    fn finish(&mut self, chunks: &mut [FileChunk]) -> Result<()> {
        self.flush(chunks)
    }

    fn fits_with(&self, encoded_len: usize) -> Result<bool> {
        let stream_len = self
            .pending_object_stream_len
            .checked_add(encoded_len)
            .ok_or_else(|| Error::SecurityLimitExceeded("page is too large".to_string()))?;
        Ok(uncompressed_objects_fit(DEFAULT_PAGE_BYTES, stream_len))
    }

    fn flush(&mut self, chunks: &mut [FileChunk]) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let page_offset = self.lockbox.allocate_page_offset()?;
        let objects = self
            .pending
            .iter()
            .map(|pending| pending.object.clone())
            .collect::<Vec<_>>();
        self.lockbox
            .write_decoded_page_at(page_offset, self.lockbox.sequence, objects)?;
        for pending in self.pending.drain(..) {
            if let Some(chunk) = chunks.get_mut(pending.chunk_index) {
                chunk.fragments.push(FileFragment {
                    page_offset,
                    page_len: DEFAULT_PAGE_BYTES as u64,
                    object_id: pending.object.id,
                    fragment_offset: pending.fragment_offset,
                    fragment_len: pending.fragment_len,
                });
            }
        }
        self.pending_object_stream_len = 4;
        Ok(())
    }
}
