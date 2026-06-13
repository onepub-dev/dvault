use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::Lockbox;
use crate::compression::{
    decode_compression_frame, encode_compression_frame_with_level, COMPRESSION_NONE,
    MAX_DECOMPRESSED_COMPRESSION_FRAME_BYTES, ZSTD_BULK_IMPORT_LEVEL, ZSTD_DEFAULT_LEVEL,
};
use crate::compression_frame_manifest::{CompressionFrameManifest, CompressionFrameSlice};
use crate::constants::{
    DEFAULT_FILE_PERMISSIONS, DEFAULT_MAX_PAGE_BODY_BYTES, DEFAULT_MAX_PAGE_LOGICAL_BYTES,
};
use crate::crypto::strong_checksum;
use crate::file_chunk::{CompressionFrameSegment, FileChunk, PendingFileChunk};
use crate::file_format::{
    decode_compression_frame_segment_payload_view, encode_compression_frame_segment_payload,
};
use crate::lockbox_path::LockboxPath;
use crate::node_kind::NodeKind;
use crate::page::{page_size_for_encoded_objects, PageObject, PageObjectKind, DEFAULT_PAGE_BYTES};
use crate::page_object_packer::PageObjectPacker;
use crate::security::validate_permissions;
use crate::toc_entry::TocEntry;
use crate::{Error, Result, WorkloadProfile};
use zeroize::{Zeroize, Zeroizing};

const SMALL_FILE_PACKING_LIMIT: usize = 1024 * 1024;
const SMALL_FILE_COMPRESSION_FRAME_BYTES: usize = 4 * 1024;
const BULK_IMPORT_SMALL_FILE_COMPRESSION_FRAME_BYTES: usize = 2 * 1024 * 1024;
const FILE_COMPRESSION_FRAME_BYTES: usize = 2 * 1024 * 1024;
const MAX_SEGMENT_BYTES: usize = DEFAULT_MAX_PAGE_BODY_BYTES - 64 * 1024;
const DECODED_COMPRESSION_FRAME_CACHE_BYTES: usize = 64 * 1024 * 1024;

impl Lockbox {
    pub(crate) fn rewrite_shared_compression_frames_before_removal(
        &mut self,
        entry: &TocEntry,
    ) -> Result<()> {
        if entry.deleted || entry.node_kind != NodeKind::File || entry.chunks.is_empty() {
            return Ok(());
        }
        let removed_compression_frames = entry
            .chunks
            .iter()
            .map(|chunk| chunk.compression_frame_id)
            .collect::<BTreeSet<_>>();
        let mut shared = BTreeSet::new();
        for other in self.toc_entries.values() {
            if other.deleted || other.path == entry.path || other.node_kind != NodeKind::File {
                continue;
            }
            if other
                .chunks
                .iter()
                .any(|chunk| removed_compression_frames.contains(&chunk.compression_frame_id))
            {
                for chunk in &other.chunks {
                    if removed_compression_frames.contains(&chunk.compression_frame_id) {
                        shared.insert(chunk.compression_frame_id);
                    }
                }
            }
        }
        if shared.is_empty() {
            return Ok(());
        }

        let mut groups: BTreeMap<u64, Vec<SharedCompressionFrameSurvivor>> = BTreeMap::new();
        for other in self.toc_entries.values() {
            if other.deleted || other.path == entry.path || other.node_kind != NodeKind::File {
                continue;
            }
            for chunk in &other.chunks {
                if shared.contains(&chunk.compression_frame_id) {
                    let data = self.read_file_chunk_compression_frame(other.len, chunk)?;
                    groups.entry(chunk.compression_frame_id).or_default().push(
                        SharedCompressionFrameSurvivor {
                            path: other.path.clone(),
                            permissions: other.permissions,
                            total_len: other.len,
                            file_offset: chunk.file_offset,
                            data,
                        },
                    );
                }
            }
        }

        let mut replacement_indices: Vec<(LockboxPath, u64, usize)> = Vec::new();
        let mut replacements: Vec<(LockboxPath, u64, FileChunk)> = Vec::new();
        {
            let mut writer = FilePageWriter::new(self);
            let mut written = Vec::new();
            for (old_compression_frame_id, survivors) in &groups {
                let writes = survivors
                    .iter()
                    .map(|survivor| CompressionFrameWrite {
                        path: &survivor.path,
                        permissions: survivor.permissions,
                        total_len: survivor.total_len,
                        file_offset: survivor.file_offset,
                        data: &survivor.data,
                    })
                    .collect::<Vec<_>>();
                let indices = writer.write_compression_frame_bundle(&writes, &mut written)?;
                for (survivor, chunk_index) in survivors.iter().zip(indices) {
                    replacement_indices.push((
                        survivor.path.clone(),
                        *old_compression_frame_id,
                        chunk_index,
                    ));
                }
            }
            writer.finish(&mut written)?;
            replacements.extend(replacement_indices.into_iter().map(
                |(path, old_compression_frame_id, chunk_index)| {
                    (path, old_compression_frame_id, written[chunk_index].clone())
                },
            ));
        }

        let mut by_path: BTreeMap<LockboxPath, Vec<(u64, FileChunk)>> = BTreeMap::new();
        for (path, old_compression_frame_id, chunk) in replacements {
            by_path
                .entry(path)
                .or_default()
                .push((old_compression_frame_id, chunk));
        }
        let mut dirty = Vec::new();
        for (path, chunks) in by_path {
            if let Some(live) = self.toc_entries.get_mut(path.as_str()) {
                let replaced_compression_frames = chunks
                    .iter()
                    .map(|(old_compression_frame_id, _)| *old_compression_frame_id)
                    .collect::<BTreeSet<_>>();
                live.chunks.retain(|chunk| {
                    !replaced_compression_frames.contains(&chunk.compression_frame_id)
                });
                live.chunks
                    .extend(chunks.into_iter().map(|(_, chunk)| chunk));
                live.chunks.sort_by_key(|chunk| chunk.file_offset);
                if let Some(first) = live.chunks.first().and_then(|chunk| chunk.segments.first()) {
                    live.record_offset = first.page_offset;
                    live.record_len = first.page_len;
                    live.record_object_id = first.object_id;
                }
                dirty.push(live.path.clone());
            }
        }
        self.mark_toc_dirty_paths(dirty.iter());
        self.rebuild_record_ref_counts();
        Ok(())
    }

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
        let stat_start = Instant::now();
        let metadata = std::fs::metadata(source)
            .map_err(|err| Error::Io(format!("stat {}: {err}", source.display())))?;
        self.add_host_stat_nanos(stat_start.elapsed().as_nanos());
        if metadata.len() <= SMALL_FILE_PACKING_LIMIT as u64 {
            let read_start = Instant::now();
            let data = std::fs::read(source)
                .map_err(|err| Error::Io(format!("read {}: {err}", source.display())))?;
            self.add_host_read_nanos(read_start.elapsed().as_nanos());
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
        reader: impl Read,
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

        let jobs = self.worker_jobs();
        let (file_offset, chunks) = if jobs > 1 {
            self.write_file_data_parallel(&path, reader, permissions, jobs)?
        } else {
            self.write_file_data_sequential(&path, reader, permissions)?
        };

        let entry = TocEntry {
            path: path.clone(),
            len: file_offset,
            record_offset: chunks
                .first()
                .and_then(|chunk| chunk.segments.first())
                .map(|segment| segment.page_offset)
                .unwrap_or(0),
            record_len: chunks
                .first()
                .and_then(|chunk| chunk.segments.first())
                .map(|segment| segment.page_len)
                .unwrap_or(0),
            record_object_id: chunks
                .first()
                .and_then(|chunk| chunk.segments.first())
                .map(|segment| segment.object_id)
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

    fn write_file_data_sequential(
        &mut self,
        path: &LockboxPath,
        mut reader: impl Read,
        permissions: u32,
    ) -> Result<(u64, Vec<FileChunk>)> {
        let mut chunks = Vec::new();
        let mut file_offset = 0u64;
        let mut writer = FilePageWriter::new(self);
        let mut buffer = vec![0; FILE_COMPRESSION_FRAME_BYTES];
        loop {
            let read_start = Instant::now();
            let read = read_next_chunk(&mut reader, &mut buffer)?;
            writer
                .lockbox
                .add_host_read_nanos(read_start.elapsed().as_nanos());
            if read == 0 {
                if file_offset == 0 {
                    writer.write_compression_frame(
                        CompressionFrameWrite {
                            path,
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
            writer.write_compression_frame(
                CompressionFrameWrite {
                    path,
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
        Ok((file_offset, chunks))
    }

    fn write_file_data_parallel(
        &mut self,
        path: &LockboxPath,
        mut reader: impl Read,
        permissions: u32,
        jobs: usize,
    ) -> Result<(u64, Vec<FileChunk>)> {
        let jobs = jobs.max(1);
        let level = self.compression_frame_zstd_level();
        let queue_bound = jobs.saturating_mul(2).max(1);
        let (job_tx, job_rx) = std::sync::mpsc::sync_channel::<ParallelCompressionJob>(queue_bound);
        let (result_tx, result_rx) = std::sync::mpsc::channel::<ParallelCompressionResult>();
        let job_rx = Arc::new(Mutex::new(job_rx));

        std::thread::scope(|scope| -> Result<(u64, Vec<FileChunk>)> {
            for _ in 0..jobs {
                let job_rx = Arc::clone(&job_rx);
                let result_tx = result_tx.clone();
                scope.spawn(move || loop {
                    let job = match job_rx.lock() {
                        Ok(rx) => rx.recv(),
                        Err(_) => return,
                    };
                    let Ok(job) = job else {
                        return;
                    };
                    let result = prepare_parallel_compression_frame(job, level);
                    if result_tx.send(result).is_err() {
                        return;
                    }
                });
            }
            drop(result_tx);

            let mut writer = FilePageWriter::new(self);
            let mut chunks = Vec::new();
            let mut pending = BTreeMap::new();
            let mut next_index = 0usize;
            let mut received_count = 0usize;
            let mut file_offset = 0u64;
            let mut job_count = 0usize;
            let mut buffer = vec![0; FILE_COMPRESSION_FRAME_BYTES];
            loop {
                let read_start = Instant::now();
                let read = read_next_chunk(&mut reader, &mut buffer)?;
                writer
                    .lockbox
                    .add_host_read_nanos(read_start.elapsed().as_nanos());
                if read == 0 {
                    if file_offset == 0 {
                        job_tx
                            .send(ParallelCompressionJob {
                                index: job_count,
                                path: path.clone(),
                                permissions,
                                total_len: 0,
                                file_offset: 0,
                                data: Vec::new(),
                            })
                            .map_err(|_| {
                                Error::Io("compression worker stopped unexpectedly".to_string())
                            })?;
                        job_count += 1;
                        drain_ready_parallel_results(
                            &result_rx,
                            &mut writer,
                            &mut chunks,
                            &mut pending,
                            &mut next_index,
                            &mut received_count,
                        )?;
                    }
                    break;
                }

                job_tx
                    .send(ParallelCompressionJob {
                        index: job_count,
                        path: path.clone(),
                        permissions,
                        total_len: 0,
                        file_offset,
                        data: buffer[..read].to_vec(),
                    })
                    .map_err(|_| {
                        Error::Io("compression worker stopped unexpectedly".to_string())
                    })?;
                file_offset += read as u64;
                job_count += 1;
                drain_ready_parallel_results(
                    &result_rx,
                    &mut writer,
                    &mut chunks,
                    &mut pending,
                    &mut next_index,
                    &mut received_count,
                )?;
            }
            drop(job_tx);

            while received_count < job_count {
                let result = result_rx.recv().map_err(|_| {
                    Error::Io("compression worker stopped unexpectedly".to_string())
                })?;
                received_count += 1;
                pending.insert(result.index, result.frame);
                while let Some(frame) = pending.remove(&next_index) {
                    writer.write_prepared_compression_frame(frame, &mut chunks)?;
                    next_index += 1;
                }
            }
            writer.finish(&mut chunks)?;
            Ok((file_offset, chunks))
        })
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
            let decoded_chunk = self.read_file_chunk_compression_frame(entry.len, &chunk)?;
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

            let decoded_chunk = self.read_file_chunk_compression_frame(entry.len, &chunk)?;

            let copy_start = offset.max(chunk_start) - chunk_start;
            let copy_end = wanted_end.min(chunk_end) - chunk_start;
            out.extend_from_slice(&decoded_chunk[copy_start as usize..copy_end as usize]);
        }
        Ok(out)
    }

    pub(crate) fn read_file_chunk_compression_frame(
        &self,
        expected_total_len: u64,
        chunk: &FileChunk,
    ) -> Result<Vec<u8>> {
        if let Some(cached) = self.read_cached_compression_frame_slice(expected_total_len, chunk)? {
            return Ok(cached);
        }
        if chunk.compressed_len > DEFAULT_MAX_PAGE_LOGICAL_BYTES as u64 {
            return Err(Error::SecurityLimitExceeded(
                "compressed compression-frame exceeds safety limit".to_string(),
            ));
        }
        if chunk.compression_frame_len > MAX_DECOMPRESSED_COMPRESSION_FRAME_BYTES {
            return Err(Error::SecurityLimitExceeded(
                "compression-frame exceeds safety limit".to_string(),
            ));
        }
        let compressed_len =
            usize::try_from(chunk.compressed_len).map_err(|_| Error::CorruptRecord)?;
        let mut stored = Zeroizing::new(vec![0u8; compressed_len]);
        let mut cache_slices = None;
        for segment in &chunk.segments {
            self.with_page_object(segment.page_offset, segment.object_id, |object| {
                object.with_payload(|payload| {
                    let decoded = decode_compression_frame_segment_payload_view(payload)?;
                    if let Some(manifest) = decoded.manifest.as_ref() {
                        if cache_slices.is_none() {
                            cache_slices = Some(manifest.slices.clone());
                        }
                    }
                    let manifest_slice_missing =
                        decoded.manifest.as_ref().is_some_and(|manifest| {
                            manifest
                                .slice_for(
                                    &chunk.stored_path,
                                    chunk.file_offset,
                                    chunk.compression_frame_offset,
                                    chunk.len,
                                )
                                .filter(|slice| {
                                    slice.total_len == 0 || slice.total_len == expected_total_len
                                })
                                .is_none()
                        });
                    if decoded.compression_frame_id != chunk.compression_frame_id
                        || decoded.compression_frame_len != chunk.compression_frame_len
                        || decoded.compressed_len != chunk.compressed_len
                        || decoded.compression != chunk.compression
                        || decoded.compression_frame_digest != chunk.compression_frame_digest
                        || manifest_slice_missing
                        || decoded.segment_offset != segment.segment_offset
                        || decoded.data.len() as u64 != segment.segment_len
                    {
                        return Err(Error::CorruptRecord);
                    }
                    let start = usize::try_from(segment.segment_offset)
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
        if strong_checksum(stored.as_slice()) != chunk.compression_frame_digest {
            return Err(Error::CorruptRecord);
        }
        let start =
            usize::try_from(chunk.compression_frame_offset).map_err(|_| Error::CorruptRecord)?;
        let len = usize::try_from(chunk.len).map_err(|_| Error::CorruptRecord)?;
        let end = start.checked_add(len).ok_or(Error::CorruptRecord)?;
        if end > usize::try_from(chunk.compression_frame_len).map_err(|_| Error::CorruptRecord)? {
            return Err(Error::CorruptRecord);
        }
        if chunk.compression == COMPRESSION_NONE {
            if end > stored.len() {
                return Err(Error::CorruptRecord);
            }
            let out = stored[start..end].to_vec();
            let decoded = std::mem::take(&mut *stored);
            self.cache_decoded_compression_frame_owned(
                chunk,
                cache_slices.unwrap_or_default(),
                decoded,
            );
            return Ok(out);
        }

        let decoded = Zeroizing::new(decode_compression_frame(
            chunk.compression,
            stored.as_slice(),
            chunk.compression_frame_len,
        )?);
        let out = decoded[start..end].to_vec();
        self.cache_decoded_compression_frame(chunk, cache_slices.unwrap_or_default(), &decoded);
        Ok(out)
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
        if let Some(old) = self.toc_entries.get(path.as_str()).cloned() {
            self.free_entry_slots(old)?;
        }

        self.insert_pending_small_file(
            path.clone(),
            PendingFileChunk {
                path: path.clone(),
                permissions,
                total_len: data.len() as u64,
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
        if self.should_discard_file_pages_after_flush()
            && self.pending_small_file_bytes >= MAX_SEGMENT_BYTES
        {
            self.flush_pending_small_files()?;
        }
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
        if self.pending_small_files.is_empty() {
            return Ok(());
        }

        let pending = std::mem::take(&mut self.pending_small_files);
        self.pending_small_file_bytes = 0;
        let compression_frame_target = self.small_file_compression_frame_target();
        let mut writer = FilePageWriter::new(self);
        let mut all_chunks = Vec::new();
        let mut updates = Vec::new();
        let mut dirty_paths = Vec::new();
        let pending = pending.into_values().collect::<Vec<_>>();
        let mut batches = Vec::new();
        let mut batch = Vec::new();
        let mut batch_bytes = 0usize;
        for chunk in &pending {
            if !batch.is_empty()
                && batch_bytes.saturating_add(chunk.data.len()) > compression_frame_target
            {
                batches.push(batch);
                batch = Vec::new();
                batch_bytes = 0;
            }
            batch_bytes = batch_bytes.saturating_add(chunk.data.len());
            batch.push(CompressionFrameWrite {
                path: &chunk.path,
                permissions: chunk.permissions,
                total_len: chunk.total_len,
                file_offset: 0,
                data: &chunk.data,
            });
        }
        if !batch.is_empty() {
            batches.push(batch);
        }
        let batch_indices = writer.write_compression_frame_batches(&batches, &mut all_chunks)?;
        for (batch, indices) in batches.iter().zip(batch_indices) {
            for (frame, chunk_index) in batch.iter().zip(indices) {
                updates.push((
                    (*frame.path).clone(),
                    frame.permissions,
                    frame.total_len,
                    chunk_index,
                ));
            }
        }
        writer.finish(&mut all_chunks)?;
        for (path, permissions, total_len, chunk_index) in updates {
            let chunks = vec![all_chunks[chunk_index].clone()];
            if let Some(entry) = writer.lockbox.toc_entries.get_mut(path.as_str()) {
                entry.record_offset = chunks
                    .first()
                    .and_then(|chunk| chunk.segments.first())
                    .map(|segment| segment.page_offset)
                    .unwrap_or(0);
                entry.record_len = chunks
                    .first()
                    .and_then(|chunk| chunk.segments.first())
                    .map(|segment| segment.page_len)
                    .unwrap_or(0);
                entry.record_object_id = chunks
                    .first()
                    .and_then(|chunk| chunk.segments.first())
                    .map(|segment| segment.object_id)
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
        self.flush_pending_small_files()
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

        let compression_frame_target = self.small_file_compression_frame_target();
        let mut writer = FilePageWriter::new(self);
        let mut all_chunks = Vec::new();
        let mut updates = Vec::new();
        let mut dirty_paths = Vec::new();
        let mut batches = Vec::new();
        let mut batch = Vec::new();
        let mut batch_bytes = 0usize;
        for (path, permissions, data, _) in &candidates {
            if !batch.is_empty()
                && batch_bytes.saturating_add(data.len()) > compression_frame_target
            {
                batches.push(batch);
                batch = Vec::new();
                batch_bytes = 0;
            }
            let len = data.len() as u64;
            batch_bytes = batch_bytes.saturating_add(data.len());
            batch.push(CompressionFrameWrite {
                path,
                permissions: *permissions,
                total_len: len,
                file_offset: 0,
                data,
            });
        }
        if !batch.is_empty() {
            batches.push(batch);
        }
        let batch_indices = writer.write_compression_frame_batches(&batches, &mut all_chunks)?;
        for (batch, indices) in batches.iter().zip(batch_indices) {
            for (frame, chunk_index) in batch.iter().zip(indices) {
                updates.push((
                    (*frame.path).clone(),
                    frame.permissions,
                    frame.total_len,
                    chunk_index,
                ));
            }
        }
        writer.finish(&mut all_chunks)?;
        for (path, permissions, len, chunk_index) in updates {
            let chunks = vec![all_chunks[chunk_index].clone()];
            if let Some(entry) = writer.lockbox.toc_entries.get_mut(path.as_str()) {
                entry.record_offset = chunks
                    .first()
                    .and_then(|chunk| chunk.segments.first())
                    .map(|segment| segment.page_offset)
                    .unwrap_or(0);
                entry.record_len = chunks
                    .first()
                    .and_then(|chunk| chunk.segments.first())
                    .map(|segment| segment.page_len)
                    .unwrap_or(0);
                entry.record_object_id = chunks
                    .first()
                    .and_then(|chunk| chunk.segments.first())
                    .map(|segment| segment.object_id)
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

    fn small_file_compression_frame_target(&self) -> usize {
        match self.workload_profile {
            WorkloadProfile::BulkImport => BULK_IMPORT_SMALL_FILE_COMPRESSION_FRAME_BYTES,
            _ => SMALL_FILE_COMPRESSION_FRAME_BYTES,
        }
    }

    fn compression_frame_zstd_level(&self) -> i32 {
        match self.workload_profile {
            WorkloadProfile::BulkImport => ZSTD_BULK_IMPORT_LEVEL,
            _ => ZSTD_DEFAULT_LEVEL,
        }
    }

    fn decoded_compression_frame_cache_limit(&self) -> usize {
        match self.workload_profile {
            WorkloadProfile::ReadMostly | WorkloadProfile::ExtractMany => {
                DECODED_COMPRESSION_FRAME_CACHE_BYTES
            }
            _ => 0,
        }
    }

    fn read_cached_compression_frame_slice(
        &self,
        expected_total_len: u64,
        chunk: &FileChunk,
    ) -> Result<Option<Vec<u8>>> {
        let cache = self.compression_frame_cache.borrow();
        let Some(entry) = cache.entries.get(&chunk.compression_frame_id) else {
            return Ok(None);
        };
        if entry.compression != chunk.compression
            || entry.compression_frame_len != chunk.compression_frame_len
            || entry.compressed_len != chunk.compressed_len
            || entry.compression_frame_digest != chunk.compression_frame_digest
        {
            return Err(Error::CorruptRecord);
        }
        let has_slice = entry.slices.iter().any(|slice| {
            slice.path == chunk.stored_path
                && slice.file_offset == chunk.file_offset
                && slice.compression_frame_offset == chunk.compression_frame_offset
                && slice.len == chunk.len
                && (slice.total_len == 0 || slice.total_len == expected_total_len)
        });
        if !has_slice {
            return Err(Error::CorruptRecord);
        }
        let start =
            usize::try_from(chunk.compression_frame_offset).map_err(|_| Error::CorruptRecord)?;
        let len = usize::try_from(chunk.len).map_err(|_| Error::CorruptRecord)?;
        let end = start.checked_add(len).ok_or(Error::CorruptRecord)?;
        if end > entry.data.len() {
            return Err(Error::CorruptRecord);
        }
        Ok(Some(entry.data[start..end].to_vec()))
    }

    fn cache_decoded_compression_frame(
        &self,
        chunk: &FileChunk,
        slices: Vec<CompressionFrameSlice>,
        decoded: &[u8],
    ) {
        if !self.should_cache_decoded_compression_frame(decoded.len()) {
            return;
        }
        self.insert_decoded_compression_frame(chunk, slices, decoded.to_vec());
    }

    fn cache_decoded_compression_frame_owned(
        &self,
        chunk: &FileChunk,
        slices: Vec<CompressionFrameSlice>,
        decoded: Vec<u8>,
    ) {
        if !self.should_cache_decoded_compression_frame(decoded.len()) {
            return;
        }
        self.insert_decoded_compression_frame(chunk, slices, decoded);
    }

    fn should_cache_decoded_compression_frame(&self, decoded_len: usize) -> bool {
        let limit = self.decoded_compression_frame_cache_limit();
        limit > 0 && decoded_len <= limit
    }

    fn insert_decoded_compression_frame(
        &self,
        chunk: &FileChunk,
        slices: Vec<CompressionFrameSlice>,
        decoded: Vec<u8>,
    ) {
        let decoded_len = decoded.len();
        let limit = self.decoded_compression_frame_cache_limit();
        let mut cache = self.compression_frame_cache.borrow_mut();
        if let Some(old) = cache.entries.remove(&chunk.compression_frame_id) {
            cache.used_bytes = cache.used_bytes.saturating_sub(old.data.len());
        }
        while cache.used_bytes.saturating_add(decoded_len) > limit {
            let Some(key) = cache.entries.keys().next().copied() else {
                break;
            };
            if let Some(old) = cache.entries.remove(&key) {
                cache.used_bytes = cache.used_bytes.saturating_sub(old.data.len());
            }
        }
        cache.entries.insert(
            chunk.compression_frame_id,
            super::CachedCompressionFrame {
                compression: chunk.compression,
                compression_frame_len: chunk.compression_frame_len,
                compressed_len: chunk.compressed_len,
                compression_frame_digest: chunk.compression_frame_digest,
                slices,
                data: decoded,
            },
        );
        cache.used_bytes = cache.used_bytes.saturating_add(decoded_len);
    }

    #[cfg(test)]
    pub(crate) fn decoded_compression_frame_cache_entries_for_tests(&self) -> usize {
        self.compression_frame_cache.borrow().entries.len()
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

fn drain_ready_parallel_results(
    result_rx: &std::sync::mpsc::Receiver<ParallelCompressionResult>,
    writer: &mut FilePageWriter<'_>,
    chunks: &mut Vec<FileChunk>,
    pending: &mut BTreeMap<usize, PreparedCompressionFrame>,
    next_index: &mut usize,
    received_count: &mut usize,
) -> Result<()> {
    loop {
        let result = match result_rx.try_recv() {
            Ok(result) => result,
            Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(()),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err(Error::Io(
                    "compression worker stopped unexpectedly".to_string(),
                ));
            }
        };
        *received_count += 1;
        pending.insert(result.index, result.frame);
        while let Some(frame) = pending.remove(&*next_index) {
            writer.write_prepared_compression_frame(frame, chunks)?;
            *next_index += 1;
        }
    }
}

#[derive(Debug, Clone)]
struct PendingSegment {
    chunk_indices: Vec<usize>,
    segment_offset: u64,
    segment_len: u64,
}

struct FilePageWriter<'a> {
    lockbox: &'a mut Lockbox,
    packer: PageObjectPacker<PendingSegment>,
}

struct SharedCompressionFrameSurvivor {
    path: LockboxPath,
    permissions: u32,
    total_len: u64,
    file_offset: u64,
    data: Vec<u8>,
}

impl Drop for SharedCompressionFrameSurvivor {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[derive(Clone, Copy)]
struct CompressionFrameWrite<'a> {
    path: &'a LockboxPath,
    permissions: u32,
    total_len: u64,
    file_offset: u64,
    data: &'a [u8],
}

struct PreparedCompressionFrame {
    compression: u8,
    compression_frame_len: u64,
    compressed_len: u64,
    compression_frame_digest: [u8; 32],
    slices: Vec<CompressionFrameSlice>,
    stored: Zeroizing<Vec<u8>>,
    prepare_nanos: u128,
}

struct ParallelCompressionJob {
    index: usize,
    path: LockboxPath,
    permissions: u32,
    total_len: u64,
    file_offset: u64,
    data: Vec<u8>,
}

impl Drop for ParallelCompressionJob {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

struct ParallelCompressionResult {
    index: usize,
    frame: PreparedCompressionFrame,
}

impl<'a> FilePageWriter<'a> {
    fn new(lockbox: &'a mut Lockbox) -> Self {
        Self {
            lockbox,
            packer: PageObjectPacker::new(DEFAULT_PAGE_BYTES),
        }
    }

    fn write_compression_frame(
        &mut self,
        frame: CompressionFrameWrite<'_>,
        chunks: &mut Vec<FileChunk>,
    ) -> Result<()> {
        self.write_compression_frame_bundle(&[frame], chunks)
            .map(|_| ())
    }

    fn write_compression_frame_bundle(
        &mut self,
        frames: &[CompressionFrameWrite<'_>],
        chunks: &mut Vec<FileChunk>,
    ) -> Result<Vec<usize>> {
        let prepared =
            prepare_compression_frame(frames, self.lockbox.compression_frame_zstd_level());
        self.write_prepared_compression_frame(prepared, chunks)
    }

    fn write_compression_frame_batches(
        &mut self,
        batches: &[Vec<CompressionFrameWrite<'_>>],
        chunks: &mut Vec<FileChunk>,
    ) -> Result<Vec<Vec<usize>>> {
        let prepared = prepare_compression_frame_batches(
            batches,
            self.lockbox.compression_frame_zstd_level(),
            self.lockbox.worker_jobs(),
        );
        let mut indices = Vec::with_capacity(prepared.len());
        for frame in prepared {
            indices.push(self.write_prepared_compression_frame(frame, chunks)?);
        }
        Ok(indices)
    }

    fn write_prepared_compression_frame(
        &mut self,
        prepared: PreparedCompressionFrame,
        chunks: &mut Vec<FileChunk>,
    ) -> Result<Vec<usize>> {
        self.lockbox.add_frame_prepare_nanos(prepared.prepare_nanos);
        self.lockbox.sequence += 1;
        let compression_frame_id = self.lockbox.sequence;
        let mut chunk_indices = Vec::with_capacity(prepared.slices.len());
        let manifest = CompressionFrameManifest {
            compression_frame_id,
            compression: prepared.compression,
            compression_frame_len: prepared.compression_frame_len,
            compressed_len: prepared.compressed_len,
            compression_frame_digest: prepared.compression_frame_digest,
            slices: prepared.slices,
        };
        for slice in &manifest.slices {
            let chunk_index = chunks.len();
            chunks.push(FileChunk {
                stored_path: slice.path.clone(),
                file_offset: slice.file_offset,
                len: slice.len,
                compression_frame_offset: slice.compression_frame_offset,
                compression_frame_len: manifest.compression_frame_len,
                compressed_len: manifest.compressed_len,
                compression: manifest.compression,
                compression_frame_id,
                compression_frame_digest: manifest.compression_frame_digest,
                segments: Vec::new(),
            });
            chunk_indices.push(chunk_index);
        }

        if prepared.stored.is_empty() {
            self.add_segment(&manifest, 0, &chunk_indices, &[], chunks)?;
            return Ok(chunk_indices);
        }

        let mut offset = 0usize;
        while offset < prepared.stored.len() {
            let end = (offset + MAX_SEGMENT_BYTES).min(prepared.stored.len());
            self.add_segment(
                &manifest,
                offset as u64,
                &chunk_indices,
                &prepared.stored[offset..end],
                chunks,
            )?;
            offset = end;
        }
        Ok(chunk_indices)
    }

    fn add_segment(
        &mut self,
        manifest: &CompressionFrameManifest,
        segment_offset: u64,
        chunk_indices: &[usize],
        segment: &[u8],
        chunks: &mut [FileChunk],
    ) -> Result<()> {
        self.lockbox.sequence += 1;
        let object_id = self.lockbox.sequence;
        let payload = encode_compression_frame_segment_payload(manifest, segment_offset, segment)?;
        let object = PageObject::new(PageObjectKind::FileData, object_id, payload);
        let context = PendingSegment {
            chunk_indices: chunk_indices.to_vec(),
            segment_offset,
            segment_len: segment.len() as u64,
        };

        let encoded_len = self.packer.encoded_object_len(&object)?;
        if !self.packer.is_empty() && !self.fits_with(encoded_len)? {
            self.flush(chunks)?;
        }
        if !self.fits_with(encoded_len)? {
            return Err(Error::SecurityLimitExceeded(
                "file segment does not fit in a page".to_string(),
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
        let write_start = Instant::now();
        let pending = self.packer.pending().to_vec();
        let objects = pending
            .iter()
            .map(|pending| pending.object.clone())
            .collect::<Vec<_>>();
        let page_size = page_size_for_encoded_objects(&objects)?;
        let page_offset = self.lockbox.allocate_page_offset(page_size as u64)?;
        if self.lockbox.should_discard_file_pages_after_flush() {
            self.lockbox
                .write_insert_only_page_at(page_offset, self.lockbox.sequence, objects)?;
            self.lockbox.flush_discardable_pages()?;
        } else {
            self.lockbox
                .write_decoded_page_at(page_offset, self.lockbox.sequence, objects)?;
        }
        for pending in pending {
            for chunk_index in pending.context.chunk_indices {
                if let Some(chunk) = chunks.get_mut(chunk_index) {
                    chunk.segments.push(CompressionFrameSegment {
                        page_offset,
                        page_len: page_size as u64,
                        object_id: pending.object.id,
                        segment_offset: pending.context.segment_offset,
                        segment_len: pending.context.segment_len,
                    });
                }
            }
        }
        self.packer.clear();
        self.lockbox
            .add_page_write_nanos(write_start.elapsed().as_nanos());
        Ok(())
    }
}

fn prepare_compression_frame(
    frames: &[CompressionFrameWrite<'_>],
    zstd_level: i32,
) -> PreparedCompressionFrame {
    let prepare_start = Instant::now();
    let mut compression_frame_payload = Vec::new();
    let mut slices = Vec::with_capacity(frames.len());
    for frame in frames {
        let compression_frame_offset = compression_frame_payload.len() as u64;
        compression_frame_payload.extend_from_slice(frame.data);
        slices.push(CompressionFrameSlice {
            path: frame.path.clone(),
            permissions: frame.permissions,
            total_len: frame.total_len,
            file_offset: frame.file_offset,
            compression_frame_offset,
            len: frame.data.len() as u64,
        });
    }
    prepare_compression_frame_payload(compression_frame_payload, slices, zstd_level, prepare_start)
}

fn prepare_compression_frame_batches(
    batches: &[Vec<CompressionFrameWrite<'_>>],
    zstd_level: i32,
    jobs: usize,
) -> Vec<PreparedCompressionFrame> {
    if jobs <= 1 || batches.len() <= 1 {
        return batches
            .iter()
            .map(|batch| prepare_compression_frame(batch, zstd_level))
            .collect();
    }

    let worker_count = jobs.min(batches.len()).max(1);
    let next_index = std::sync::atomic::AtomicUsize::new(0);
    let (result_tx, result_rx) = std::sync::mpsc::channel::<(usize, PreparedCompressionFrame)>();
    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            let result_tx = result_tx.clone();
            let next_index = &next_index;
            scope.spawn(move || loop {
                let index = next_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if index >= batches.len() {
                    return;
                }
                let prepared = prepare_compression_frame(&batches[index], zstd_level);
                if result_tx.send((index, prepared)).is_err() {
                    return;
                }
            });
        }
        drop(result_tx);
    });

    let mut prepared = Vec::with_capacity(batches.len());
    prepared.resize_with(batches.len(), || None);
    for (index, frame) in result_rx {
        prepared[index] = Some(frame);
    }
    prepared
        .into_iter()
        .enumerate()
        .map(|(index, frame)| {
            frame.unwrap_or_else(|| prepare_compression_frame(&batches[index], zstd_level))
        })
        .collect()
}

fn prepare_parallel_compression_frame(
    mut job: ParallelCompressionJob,
    zstd_level: i32,
) -> ParallelCompressionResult {
    let prepare_start = Instant::now();
    let index = job.index;
    let slice = CompressionFrameSlice {
        path: job.path.clone(),
        permissions: job.permissions,
        total_len: job.total_len,
        file_offset: job.file_offset,
        compression_frame_offset: 0,
        len: job.data.len() as u64,
    };
    let frame = prepare_compression_frame_payload(
        std::mem::take(&mut job.data),
        vec![slice],
        zstd_level,
        prepare_start,
    );
    ParallelCompressionResult { index, frame }
}

fn prepare_compression_frame_payload(
    mut compression_frame_payload: Vec<u8>,
    slices: Vec<CompressionFrameSlice>,
    zstd_level: i32,
    prepare_start: Instant,
) -> PreparedCompressionFrame {
    let compression_frame_len = compression_frame_payload.len() as u64;
    let (compression, stored) =
        encode_compression_frame_with_level(&compression_frame_payload, zstd_level);
    compression_frame_payload.zeroize();
    let stored = Zeroizing::new(stored);
    let compression_frame_digest = strong_checksum(stored.as_slice());
    let prepare_nanos = prepare_start.elapsed().as_nanos();
    PreparedCompressionFrame {
        compression,
        compression_frame_len,
        compressed_len: stored.len() as u64,
        compression_frame_digest,
        slices,
        stored,
        prepare_nanos,
    }
}
