use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::sync::Arc;

use super::Lockbox;
use crate::compression::{decode_file_frame, encode_file_frame};
use crate::constants::{
    DEFAULT_FILE_PERMISSIONS, DEFAULT_MAX_PAGE_BODY_BYTES, DEFAULT_MAX_PAGE_LOGICAL_BYTES,
};
use crate::file_chunk::{FileChunk, FileFragment, PackedSmallFile, PendingFileChunk};
use crate::file_format::{decode_file_fragment_payload_view, encode_file_fragment_payload};
use crate::lockbox_path::LockboxPath;
use crate::node_kind::NodeKind;
use crate::page::{PageObject, PageObjectKind, DEFAULT_PAGE_BYTES};
use crate::page_object_packer::{PackedPageObject, PageObjectPacker};
use crate::security::validate_permissions;
use crate::toc_entry::TocEntry;
use crate::{Error, Result};

const SMALL_FILE_PACKING_LIMIT: usize = 1024 * 1024;
const FILE_FRAME_BYTES: usize = 1020 * 1024;
const MAX_FRAGMENT_BYTES: usize = DEFAULT_MAX_PAGE_BODY_BYTES - 64 * 1024;

impl Lockbox {
    pub(crate) fn validate_replace_intent(&self, path: &LockboxPath, replace: bool) -> Result<()> {
        let exists = self.exists(path);
        match (replace, exists) {
            (false, true) => Err(Error::AlreadyExists(path.to_string())),
            (true, false) => Err(Error::NotFound(path.to_string())),
            _ => Ok(()),
        }
    }

    /// Add or replace a file from an in-memory byte slice.
    ///
    /// When `replace` is `false`, returns `Error::AlreadyExists` if `path`
    /// already names an existing file or symlink. When `replace` is `true`,
    /// returns `Error::NotFound` if there is no existing entry to replace. Returns
    /// `Error::InvalidPath` for directory-only or unsafe lockbox paths and
    /// propagates storage or encoding errors from the write.
    pub fn add_file(&mut self, path: &LockboxPath, data: &[u8], replace: bool) -> Result<()> {
        self.add_file_with_permissions(path, data, DEFAULT_FILE_PERMISSIONS, replace)
    }

    /// Add or replace a file with explicit Unix-style permissions.
    ///
    /// `permissions` is a Unix mode value containing only the low permission
    /// bits, written in Rust as octal literals such as `0o600`, `0o640`, or
    /// `0o755`. File type bits, sticky/setuid/setgid bits, and platform ACLs
    /// are not supported.
    ///
    /// When `replace` is `false`, returns `Error::AlreadyExists` if `path`
    /// already names an existing file or symlink. When `replace` is `true`,
    /// returns `Error::NotFound` if there is no existing entry to replace. Returns
    /// `Error::InvalidPath` for directory-only or unsafe lockbox paths,
    /// `Error::InvalidPath` for unsupported permission bits, and propagates
    /// storage or encoding errors from the write.
    pub fn add_file_with_permissions(
        &mut self,
        path: &LockboxPath,
        data: &[u8],
        permissions: u32,
        replace: bool,
    ) -> Result<()> {
        if data.len() <= SMALL_FILE_PACKING_LIMIT {
            return self.stage_small_file(path, data, permissions, replace);
        }
        self.add_file_from_reader_with_permissions(path, Cursor::new(data), permissions, replace)
    }

    /// Add or replace a file by streaming bytes from a reader.
    ///
    /// When `replace` is `false`, returns `Error::AlreadyExists` if `path`
    /// already names an existing file or symlink. When `replace` is `true`,
    /// returns `Error::NotFound` if there is no existing entry to replace. Returns
    /// `Error::InvalidPath` for directory-only or unsafe lockbox paths and
    /// propagates reader, storage, or encoding errors from the write.
    pub fn add_file_from_reader(
        &mut self,
        path: &LockboxPath,
        reader: impl Read,
        replace: bool,
    ) -> Result<()> {
        self.add_file_from_reader_with_permissions(path, reader, DEFAULT_FILE_PERMISSIONS, replace)
    }

    /// Add or replace a file by reading from a host filesystem path.
    ///
    /// When `replace` is `false`, returns `Error::AlreadyExists` if
    /// `destination` already names an existing file or symlink. When `replace`
    /// is `true`, returns `Error::NotFound` if there is no existing entry to replace.
    /// Returns `Error::InvalidPath` for directory-only or unsafe destination
    /// paths and `Error::Io` if the host file cannot be read.
    pub fn add_file_from_path(
        &mut self,
        source: &Path,
        destination: &LockboxPath,
        replace: bool,
    ) -> Result<()> {
        let metadata = std::fs::metadata(source)
            .map_err(|err| Error::Io(format!("stat {}: {err}", source.display())))?;
        if metadata.len() <= SMALL_FILE_PACKING_LIMIT as u64 {
            let data = std::fs::read(source)
                .map_err(|err| Error::Io(format!("read {}: {err}", source.display())))?;
            return self.add_file(destination, &data, replace);
        }
        let file = std::fs::File::open(source)
            .map_err(|err| Error::Io(format!("open {}: {err}", source.display())))?;
        self.add_file_from_reader(destination, file, replace)
    }

    /// Add or replace a streamed file with explicit Unix-style permissions.
    ///
    /// `permissions` is a Unix mode value containing only the low permission
    /// bits, written in Rust as octal literals such as `0o600`, `0o640`, or
    /// `0o755`. File type bits, sticky/setuid/setgid bits, and platform ACLs
    /// are not supported.
    ///
    /// When `replace` is `false`, returns `Error::AlreadyExists` if `path`
    /// already names an existing file or symlink. When `replace` is `true`,
    /// returns `Error::NotFound` if there is no existing entry to replace. Returns
    /// `Error::InvalidPath` for directory-only or unsafe lockbox paths,
    /// `Error::InvalidPath` for unsupported permission bits, and propagates
    /// reader, storage, or encoding errors from the write.
    pub fn add_file_from_reader_with_permissions(
        &mut self,
        path: &LockboxPath,
        reader: impl Read,
        permissions: u32,
        replace: bool,
    ) -> Result<()> {
        self.write_file_from_reader_with_permissions(path, reader, permissions, replace)
    }

    fn write_file_from_reader_with_permissions(
        &mut self,
        path: &LockboxPath,
        mut reader: impl Read,
        permissions: u32,
        replace: bool,
    ) -> Result<()> {
        let path = path.file_path()?;
        let permissions = validate_permissions(permissions)?;
        self.validate_replace_intent(&path, replace)?;
        if self.should_discard_file_pages_after_flush()
            && self.pending_small_files.contains_key(path.as_str())
        {
            self.flush_bulk_small_file_packer()?;
        }
        self.remove_pending_small_file(&path);
        if let Some(old) = self.toc_entries.get(path.as_str()).cloned() {
            self.free_entry_slots(old)?;
        }

        let mut chunks = Vec::new();
        let mut file_offset = 0u64;
        let mut writer = FilePageWriter::new(self);
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
                },
                &mut chunks,
            )?;
            file_offset += read as u64;
        }
        writer.finish(&mut chunks)?;

        let entry = TocEntry {
            path: path.clone(),
            len: file_offset,
            record_offset: chunks
                .first()
                .and_then(|chunk| chunk.fragments.first())
                .map(|fragment| fragment.page_offset)
                .unwrap_or(0),
            record_len: DEFAULT_PAGE_BYTES as u64,
            record_object_id: chunks
                .first()
                .and_then(|chunk| chunk.fragments.first())
                .map(|fragment| fragment.object_id)
                .unwrap_or(0),
            deleted: false,
            node_kind: NodeKind::File,
            permissions,
            chunks,
        };
        self.add_entry_record_refs(&entry);
        self.toc_entries.insert(path.clone(), entry);
        self.mark_toc_dirty(&path);
        self.needs_packing = true;
        Ok(())
    }

    /// Return the complete contents of a file.
    ///
    /// Returns `Error::InvalidPath` for directory-only paths, `Error::NotFound`
    /// if `path` is absent or not a file, `Error::CorruptRecord` if stored file
    /// metadata is inconsistent, and `Error::Io` if an internal write into the
    /// output buffer fails.
    pub fn get_file(&self, path: &LockboxPath) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.extract_file_to_writer(path, &mut out)?;
        Ok(out)
    }

    /// Extract a file's contents to a writer.
    ///
    /// Returns `Error::InvalidPath` for directory-only paths, `Error::NotFound`
    /// if `path` is absent or not a file, `Error::CorruptRecord` if stored file
    /// metadata is inconsistent, and `Error::Io` if the writer fails.
    pub fn extract_file_to_writer(&self, path: &LockboxPath, mut writer: impl Write) -> Result<()> {
        let path = path.as_file_path()?;
        let entry = self
            .toc_entries
            .get(path)
            .filter(|entry| !entry.deleted && entry.node_kind == NodeKind::File)
            .ok_or_else(|| Error::NotFound(path.to_string()))?;

        if let Some(pending) = self.pending_small_files.get(path) {
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
        let mut written = 0u64;
        for chunk in chunks {
            if chunk.file_offset != written {
                return Err(Error::CorruptRecord);
            }
            let decoded_chunk = self.read_file_chunk_frame(entry.len, &chunk)?;
            writer
                .write_all(&decoded_chunk)
                .map_err(|err| Error::Io(err.to_string()))?;
            written = written.saturating_add(decoded_chunk.len() as u64);
            if written > entry.len {
                return Err(Error::CorruptRecord);
            }
        }
        if written != entry.len {
            return Err(Error::CorruptRecord);
        }
        Ok(())
    }

    /// Extract a file's contents to a host filesystem path.
    ///
    /// When `replace` is `false`, returns `Error::AlreadyExists` if the
    /// destination path already exists. When `replace` is `true`, returns
    /// `Error::NotFound` if the destination path does not already exist.
    /// Returns `Error::Io` if the destination file cannot be created. Returns
    /// the same errors as `extract_file_to_writer` for lockbox read failures.
    pub fn extract_file_to(
        &self,
        source: &LockboxPath,
        destination: &Path,
        replace: bool,
    ) -> Result<()> {
        let destination_exists = destination.exists();
        match (replace, destination_exists) {
            (false, true) => {
                return Err(Error::AlreadyExists(destination.display().to_string()));
            }
            (true, false) => {
                return Err(Error::NotFound(destination.display().to_string()));
            }
            _ => {}
        }
        let mut file = std::fs::File::create(destination)
            .map_err(|err| Error::Io(format!("create {}: {err}", destination.display())))?;
        self.extract_file_to_writer(source, &mut file)
    }

    /// Return stored Unix-style permissions for a file or symlink.
    ///
    /// The returned value uses the low Unix permission bits only, for example
    /// `0o600`, `0o640`, or `0o755`.
    pub fn permissions(&self, path: &LockboxPath) -> Option<u32> {
        let path = path.as_file_path().ok()?;
        self.toc_entries
            .get(path)
            .filter(|entry| !entry.deleted)
            .map(|entry| entry.permissions)
    }

    /// Read a bounded byte range from a file.
    ///
    /// Returns `Error::InvalidPath` for directory-only paths, `Error::NotFound`
    /// if `path` is absent or not a file, and `Error::CorruptRecord` if stored
    /// file metadata is inconsistent. A range outside the file returns an empty
    /// vector rather than an error.
    pub fn read_file_range(&self, path: &LockboxPath, offset: u64, len: u64) -> Result<Vec<u8>> {
        let path = path.as_file_path()?;
        let entry = self
            .toc_entries
            .get(path)
            .filter(|entry| !entry.deleted && entry.node_kind == NodeKind::File)
            .ok_or_else(|| Error::NotFound(path.to_string()))?;
        if len == 0 || offset >= entry.len {
            return Ok(Vec::new());
        }
        let wanted_end = offset.saturating_add(len).min(entry.len);

        if let Some(pending) = self.pending_small_files.get(path) {
            let start = offset.min(pending.data.len() as u64) as usize;
            let end = wanted_end.min(pending.data.len() as u64) as usize;
            return Ok(pending.data[start..end].to_vec());
        }

        if entry.chunks.is_empty() {
            return Err(Error::CorruptRecord);
        }

        let capacity = usize::try_from(wanted_end - offset).map_err(|_| {
            Error::SecurityLimitExceeded("requested range exceeds addressable memory".to_string())
        })?;
        let mut out = Vec::with_capacity(capacity);
        let mut chunks = entry.chunks.clone();
        chunks.sort_by_key(|chunk| chunk.file_offset);
        for chunk in chunks {
            let chunk_start = chunk.file_offset;
            let chunk_end = chunk.file_offset.saturating_add(chunk.len);
            if chunk_end <= offset || chunk_start >= wanted_end {
                continue;
            }

            let decoded_chunk = self.read_file_chunk_frame(entry.len, &chunk)?;

            let copy_start = offset.max(chunk_start) - chunk_start;
            let copy_end = wanted_end.min(chunk_end) - chunk_start;
            out.extend_from_slice(&decoded_chunk[copy_start as usize..copy_end as usize]);
        }
        Ok(out)
    }

    pub(crate) fn read_file_chunk_frame(
        &self,
        expected_total_len: u64,
        chunk: &FileChunk,
    ) -> Result<Vec<u8>> {
        if chunk.compressed_len > DEFAULT_MAX_PAGE_LOGICAL_BYTES as u64 {
            return Err(Error::SecurityLimitExceeded(
                "compressed file frame exceeds safety limit".to_string(),
            ));
        }
        let compressed_len =
            usize::try_from(chunk.compressed_len).map_err(|_| Error::CorruptRecord)?;
        let mut stored = vec![0u8; compressed_len];
        for fragment in &chunk.fragments {
            self.with_page_object(fragment.page_offset, fragment.object_id, |object| {
                object.with_payload(|payload| {
                    let decoded = decode_file_fragment_payload_view(payload)?;
                    if decoded.path != chunk.stored_path
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
                    let start = usize::try_from(fragment.fragment_offset)
                        .map_err(|_| Error::CorruptRecord)?;
                    let end = start
                        .checked_add(decoded.data.len())
                        .ok_or(Error::CorruptRecord)?;
                    if end > stored.len() {
                        return Err(Error::CorruptRecord);
                    }
                    stored[start..end].copy_from_slice(decoded.data);
                    Ok(())
                })?
            })?;
        }
        decode_file_frame(chunk.compression, &stored, chunk.len)
    }

    fn stage_small_file(
        &mut self,
        path: &LockboxPath,
        data: &[u8],
        permissions: u32,
        replace: bool,
    ) -> Result<()> {
        let path = path.file_path()?;
        let permissions = validate_permissions(permissions)?;
        self.validate_replace_intent(&path, replace)?;
        if self.should_discard_file_pages_after_flush() {
            return self.stage_bulk_small_file(path, data, permissions, replace);
        }
        if let Some(old) = self.toc_entries.get(path.as_str()).cloned() {
            self.free_entry_slots(old)?;
        }

        self.insert_pending_small_file(
            path.clone(),
            PendingFileChunk {
                path: path.clone(),
                permissions,
                total_len: data.len() as u64,
                file_offset: 0,
                data: Arc::from(data),
            },
        );
        self.toc_entries.insert(
            path.clone(),
            TocEntry {
                path: path.clone(),
                len: data.len() as u64,
                record_offset: 0,
                record_len: 0,
                record_object_id: 0,
                deleted: false,
                node_kind: NodeKind::File,
                permissions,
                chunks: Vec::new(),
            },
        );
        self.mark_toc_dirty(&path);
        Ok(())
    }

    fn stage_bulk_small_file(
        &mut self,
        path: LockboxPath,
        data: &[u8],
        permissions: u32,
        replace: bool,
    ) -> Result<()> {
        self.validate_replace_intent(&path, replace)?;
        if self.toc_entries.contains_key(path.as_str()) {
            self.flush_bulk_small_file_packer()?;
            if let Some(old) = self.toc_entries.get(path.as_str()).cloned() {
                self.free_entry_slots(old)?;
            }
        }

        let pending = PendingFileChunk {
            path: path.clone(),
            permissions,
            total_len: data.len() as u64,
            file_offset: 0,
            data: Arc::from(data),
        };
        let (compression, stored) = encode_file_frame(data);
        self.sequence += 1;
        let frame_id = self.sequence;
        self.sequence += 1;
        let object_id = self.sequence;
        let object = PageObject::new(
            PageObjectKind::FileData,
            object_id,
            encode_file_fragment_payload(
                &PendingFileChunk {
                    path: path.clone(),
                    permissions,
                    total_len: data.len() as u64,
                    file_offset: 0,
                    data: Arc::from(stored.as_slice()),
                },
                compression,
                frame_id,
                data.len() as u64,
                stored.len() as u64,
                0,
            ),
        );
        let context = PackedSmallFile {
            path: path.clone(),
            permissions,
            total_len: data.len() as u64,
            len: data.len() as u64,
            compressed_len: stored.len() as u64,
            compression,
            frame_id,
            object_id,
            fragment_len: stored.len() as u64,
        };
        self.push_bulk_small_file_object(object, context)?;

        self.insert_pending_small_file(path.clone(), pending);
        self.toc_entries.insert(
            path.clone(),
            TocEntry {
                path: path.clone(),
                len: data.len() as u64,
                record_offset: 0,
                record_len: 0,
                record_object_id: 0,
                deleted: false,
                node_kind: NodeKind::File,
                permissions,
                chunks: Vec::new(),
            },
        );
        self.mark_toc_dirty(&path);
        Ok(())
    }

    pub(crate) fn remove_pending_small_file(
        &mut self,
        path: &LockboxPath,
    ) -> Option<PendingFileChunk> {
        let removed = self.pending_small_files.remove(path);
        if let Some(pending) = removed.as_ref() {
            self.pending_small_file_bytes = self
                .pending_small_file_bytes
                .saturating_sub(pending.data.len());
        }
        removed
    }

    pub(crate) fn insert_pending_small_file(
        &mut self,
        path: LockboxPath,
        pending: PendingFileChunk,
    ) {
        let pending_len = pending.data.len();
        if let Some(old) = self.pending_small_files.insert(path, pending) {
            self.pending_small_file_bytes =
                self.pending_small_file_bytes.saturating_sub(old.data.len());
        }
        self.pending_small_file_bytes = self.pending_small_file_bytes.saturating_add(pending_len);
    }

    pub(crate) fn flush_pending_small_files(&mut self) -> Result<()> {
        if self.should_discard_file_pages_after_flush() {
            return self.flush_bulk_small_file_packer();
        }
        if self.pending_small_files.is_empty() {
            return Ok(());
        }

        let pending = std::mem::take(&mut self.pending_small_files);
        self.pending_small_file_bytes = 0;
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
                },
                &mut all_chunks,
            )?;
            updates.push((chunk.path, chunk.permissions, chunk.total_len, start));
        }
        writer.finish(&mut all_chunks)?;
        for (path, permissions, total_len, start) in updates {
            let chunks = all_chunks[start..start + 1].to_vec();
            if let Some(entry) = writer.lockbox.toc_entries.get_mut(path.as_str()) {
                entry.record_offset = chunks
                    .first()
                    .and_then(|chunk| chunk.fragments.first())
                    .map(|fragment| fragment.page_offset)
                    .unwrap_or(0);
                entry.record_len = DEFAULT_PAGE_BYTES as u64;
                entry.record_object_id = chunks
                    .first()
                    .and_then(|chunk| chunk.fragments.first())
                    .map(|fragment| fragment.object_id)
                    .unwrap_or(0);
                entry.len = total_len;
                entry.permissions = permissions;
                entry.chunks = chunks;
                dirty_paths.push(entry.path.clone());
                let entry = entry.clone();
                writer.lockbox.add_entry_record_refs(&entry);
            }
        }
        writer.lockbox.mark_toc_dirty_paths(dirty_paths.iter());
        Ok(())
    }

    pub(crate) fn flush_bulk_small_file_packer(&mut self) -> Result<()> {
        let mut packer = std::mem::take(&mut self.bulk_small_file_packer);
        let result = if packer.is_empty() {
            Ok(())
        } else {
            self.write_bulk_small_file_page(packer.pending())?;
            packer.clear();
            Ok(())
        };
        self.bulk_small_file_packer = packer;
        result
    }

    fn push_bulk_small_file_object(
        &mut self,
        object: PageObject,
        context: PackedSmallFile,
    ) -> Result<()> {
        let mut packer = std::mem::take(&mut self.bulk_small_file_packer);
        let result = (|| {
            let encoded_len = packer.encoded_object_len(&object)?;
            if !packer.is_empty() && !packer.fits_encoded_len(encoded_len)? {
                self.write_bulk_small_file_page(packer.pending())?;
                packer.clear();
            }
            packer.push_encoded(object, context, encoded_len)
        })();
        self.bulk_small_file_packer = packer;
        result
    }

    fn write_bulk_small_file_page(
        &mut self,
        pending: &[PackedPageObject<PackedSmallFile>],
    ) -> Result<()> {
        if pending.is_empty() {
            return Ok(());
        }
        let page_offset = self.allocate_page_offset(DEFAULT_PAGE_BYTES as u64)?;
        let objects = pending
            .iter()
            .map(|pending| pending.object.clone())
            .collect::<Vec<_>>();
        self.write_insert_only_page_at(page_offset, self.sequence, objects)?;
        self.flush_discardable_pages()?;

        let mut dirty_paths = Vec::new();
        for pending in pending {
            let packed = &pending.context;
            let chunks = vec![FileChunk {
                stored_path: packed.path.clone(),
                file_offset: 0,
                len: packed.len,
                compressed_len: packed.compressed_len,
                compression: packed.compression,
                frame_id: packed.frame_id,
                fragments: vec![FileFragment {
                    page_offset,
                    page_len: DEFAULT_PAGE_BYTES as u64,
                    object_id: packed.object_id,
                    fragment_offset: 0,
                    fragment_len: packed.fragment_len,
                }],
            }];
            self.remove_pending_small_file(&packed.path);
            if let Some(entry) = self.toc_entries.get_mut(packed.path.as_str()) {
                entry.record_offset = page_offset;
                entry.record_len = DEFAULT_PAGE_BYTES as u64;
                entry.record_object_id = packed.object_id;
                entry.len = packed.total_len;
                entry.permissions = packed.permissions;
                entry.chunks = chunks;
                dirty_paths.push(entry.path.clone());
                let entry = entry.clone();
                self.add_entry_record_refs(&entry);
            }
        }
        self.mark_toc_dirty_paths(dirty_paths.iter());
        Ok(())
    }

    pub(crate) fn pack_small_file_pages(&mut self) -> Result<()> {
        let mut candidates = Vec::new();
        for entry in self.toc_entries.values() {
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
                },
                &mut all_chunks,
            )?;
            updates.push((path, permissions, len, start));
        }
        writer.finish(&mut all_chunks)?;
        for (path, permissions, len, start) in updates {
            let chunks = all_chunks[start..start + 1].to_vec();
            if let Some(entry) = writer.lockbox.toc_entries.get_mut(path.as_str()) {
                entry.record_offset = chunks
                    .first()
                    .and_then(|chunk| chunk.fragments.first())
                    .map(|fragment| fragment.page_offset)
                    .unwrap_or(0);
                entry.record_len = DEFAULT_PAGE_BYTES as u64;
                entry.record_object_id = chunks
                    .first()
                    .and_then(|chunk| chunk.fragments.first())
                    .map(|fragment| fragment.object_id)
                    .unwrap_or(0);
                entry.len = len;
                entry.permissions = permissions;
                entry.chunks = chunks;
                dirty_paths.push(entry.path.clone());
                let entry = entry.clone();
                writer.lockbox.add_entry_record_refs(&entry);
            }
        }
        writer.lockbox.mark_toc_dirty_paths(dirty_paths.iter());
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

#[derive(Debug, Clone)]
struct PendingFragment {
    chunk_index: usize,
    fragment_offset: u64,
    fragment_len: u64,
}

struct FilePageWriter<'a> {
    lockbox: &'a mut Lockbox,
    packer: PageObjectPacker<PendingFragment>,
}

#[derive(Clone, Copy)]
struct FileFrameWrite<'a> {
    path: &'a LockboxPath,
    permissions: u32,
    total_len: u64,
    file_offset: u64,
    data: &'a [u8],
}

impl<'a> FilePageWriter<'a> {
    fn new(lockbox: &'a mut Lockbox) -> Self {
        Self {
            lockbox,
            packer: PageObjectPacker::new(DEFAULT_PAGE_BYTES),
        }
    }

    fn write_frame(
        &mut self,
        frame: FileFrameWrite<'_>,
        chunks: &mut Vec<FileChunk>,
    ) -> Result<()> {
        let (compression, stored) = encode_file_frame(frame.data);
        self.lockbox.sequence += 1;
        let frame_id = self.lockbox.sequence;
        let chunk_index = chunks.len();
        chunks.push(FileChunk {
            stored_path: frame.path.clone(),
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
        path: &LockboxPath,
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
                path: path.clone(),
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
        let object = PageObject::new(PageObjectKind::FileData, object_id, payload);
        let context = PendingFragment {
            chunk_index,
            fragment_offset,
            fragment_len: fragment.len() as u64,
        };

        let encoded_len = self.packer.encoded_object_len(&object)?;
        if !self.packer.is_empty() && !self.fits_with(encoded_len)? {
            self.flush(chunks)?;
        }
        if !self.fits_with(encoded_len)? {
            return Err(Error::SecurityLimitExceeded(
                "file fragment does not fit in a page".to_string(),
            ));
        }
        self.packer.push_encoded(object, context, encoded_len)?;
        Ok(())
    }

    fn finish(&mut self, chunks: &mut [FileChunk]) -> Result<()> {
        self.flush(chunks)
    }

    fn fits_with(&self, encoded_len: usize) -> Result<bool> {
        self.packer.fits_encoded_len(encoded_len)
    }

    fn flush(&mut self, chunks: &mut [FileChunk]) -> Result<()> {
        if self.packer.is_empty() {
            return Ok(());
        }
        let page_offset = self
            .lockbox
            .allocate_page_offset(DEFAULT_PAGE_BYTES as u64)?;
        let pending = self.packer.pending().to_vec();
        let objects = pending
            .iter()
            .map(|pending| pending.object.clone())
            .collect::<Vec<_>>();
        if self.lockbox.should_discard_file_pages_after_flush() {
            self.lockbox
                .write_insert_only_page_at(page_offset, self.lockbox.sequence, objects)?;
            self.lockbox.flush_discardable_pages()?;
        } else {
            self.lockbox
                .write_decoded_page_at(page_offset, self.lockbox.sequence, objects)?;
        }
        for pending in pending {
            if let Some(chunk) = chunks.get_mut(pending.context.chunk_index) {
                chunk.fragments.push(FileFragment {
                    page_offset,
                    page_len: DEFAULT_PAGE_BYTES as u64,
                    object_id: pending.object.id,
                    fragment_offset: pending.context.fragment_offset,
                    fragment_len: pending.context.fragment_len,
                });
            }
        }
        self.packer.clear();
        Ok(())
    }
}
