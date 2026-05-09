use super::Lockbox;
use crate::fast_hash::FastBuildHasher;
use crate::format::{file_segment_chunk_count, for_each_file_segment_chunk_trusted_toc};
use crate::host_path::HostPath;
use crate::logical_path::{canonicalize_stored_path, validate_symlink_paths as validate_symlink};
use crate::manifest_entry::ManifestEntry;
use crate::node_kind::NodeKind;
use crate::{Error, ExtractPolicy, ExtractedFile, ExtractedNode, ExtractedSymlink, Result};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

type PathIds<'a> = HashMap<&'a str, u64, FastBuildHasher>;
type DecodedSegmentCache = HashMap<u64, Vec<(u128, Vec<u8>)>, FastBuildHasher>;

impl Lockbox {
    pub fn extract_all(&self, policy: &ExtractPolicy) -> Result<Vec<ExtractedFile>> {
        let live_entries: Vec<_> = self
            .manifest
            .values()
            .filter(|entry| !entry.deleted && entry.node_kind == NodeKind::File)
            .collect();

        if live_entries.len() > policy.max_files {
            return Err(Error::SecurityLimitExceeded(format!(
                "file count {} exceeds limit {}",
                live_entries.len(),
                policy.max_files
            )));
        }

        let mut total = 0u64;
        let mut extracted = Vec::with_capacity(live_entries.len());
        let path_ids = build_path_ids(&live_entries);
        let mut cache = HashMap::with_hasher(FastBuildHasher::default());
        for (path_id, entry) in live_entries.into_iter().enumerate() {
            if entry.len > policy.max_file_bytes {
                return Err(Error::SecurityLimitExceeded(format!(
                    "{} is {} bytes, limit is {}",
                    entry.path, entry.len, policy.max_file_bytes
                )));
            }
            total = total.checked_add(entry.len).ok_or_else(|| {
                Error::SecurityLimitExceeded("total extracted size overflow".to_string())
            })?;
            if total > policy.max_total_bytes {
                return Err(Error::SecurityLimitExceeded(format!(
                    "total extracted bytes {total} exceeds limit {}",
                    policy.max_total_bytes
                )));
            }
            let bytes =
                self.read_file_entry_cached(entry, path_id as u64, &path_ids, &mut cache)?;
            if bytes.len() as u64 != entry.len {
                return Err(Error::CorruptRecord);
            }
            extracted.push(ExtractedFile {
                path: entry.path.clone(),
                bytes,
                permissions: entry.permissions,
            });
        }
        Ok(extracted)
    }

    pub fn extract_all_nodes(&self, policy: &ExtractPolicy) -> Result<Vec<ExtractedNode>> {
        let live_entries: Vec<_> = self
            .manifest
            .values()
            .filter(|entry| !entry.deleted)
            .collect();

        if live_entries.len() > policy.max_files {
            return Err(Error::SecurityLimitExceeded(format!(
                "node count {} exceeds limit {}",
                live_entries.len(),
                policy.max_files
            )));
        }

        let mut total = 0u64;
        let mut extracted = Vec::with_capacity(live_entries.len());
        let path_ids = build_path_ids(&live_entries);
        let mut cache = HashMap::with_hasher(FastBuildHasher::default());
        for (path_id, entry) in live_entries.into_iter().enumerate() {
            match entry.node_kind {
                NodeKind::File => {
                    if entry.len > policy.max_file_bytes {
                        return Err(Error::SecurityLimitExceeded(format!(
                            "{} is {} bytes, limit is {}",
                            entry.path, entry.len, policy.max_file_bytes
                        )));
                    }
                    total = total.checked_add(entry.len).ok_or_else(|| {
                        Error::SecurityLimitExceeded("total extracted size overflow".to_string())
                    })?;
                    if total > policy.max_total_bytes {
                        return Err(Error::SecurityLimitExceeded(format!(
                            "total extracted bytes {total} exceeds limit {}",
                            policy.max_total_bytes
                        )));
                    }
                    let bytes =
                        self.read_file_entry_cached(entry, path_id as u64, &path_ids, &mut cache)?;
                    extracted.push(ExtractedNode::File(ExtractedFile {
                        path: entry.path.clone(),
                        bytes,
                        permissions: entry.permissions,
                    }));
                }
                NodeKind::Symlink => {
                    if !policy.restore_symlinks {
                        continue;
                    }
                    let target = self.get_symlink_target(&entry.path)?;
                    validate_symlink(&entry.path, &target)?;
                    extracted.push(ExtractedNode::Symlink(ExtractedSymlink {
                        path: entry.path.clone(),
                        target,
                    }));
                }
            }
        }
        Ok(extracted)
    }

    pub fn extract_to_directory(
        &self,
        destination: impl AsRef<Path>,
        policy: &ExtractPolicy,
    ) -> Result<()> {
        let destination = HostPath::new(destination);
        let destination = destination.as_path();
        if !destination.exists() {
            return self.extract_to_new_directory(destination, policy);
        }

        fs::create_dir_all(destination).map_err(|err| Error::Io(err.to_string()))?;
        let destination = destination
            .canonicalize()
            .map_err(|err| Error::Io(err.to_string()))?;
        self.extract_entries_to_directory(&destination, policy)
    }

    fn extract_to_new_directory(&self, destination: &Path, policy: &ExtractPolicy) -> Result<()> {
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|err| Error::Io(err.to_string()))?;
        let parent = parent
            .canonicalize()
            .map_err(|err| Error::Io(err.to_string()))?;
        let Some(file_name) = destination.file_name() else {
            return Err(Error::Io("destination must name a directory".to_string()));
        };
        let final_destination = parent.join(file_name);
        let (temp_path, temp_root) = create_temp_directory(&parent)?;
        let extract_result = self.extract_entries_to_directory(&temp_root, policy);
        if let Err(err) = extract_result {
            let _ = fs::remove_dir_all(&temp_path);
            return Err(err);
        }
        if final_destination.exists() && !policy.overwrite {
            let _ = fs::remove_dir_all(&temp_path);
            return Err(Error::SecurityLimitExceeded(format!(
                "destination exists: {}",
                final_destination.display()
            )));
        }
        if let Err(err) = move_directory(&temp_path, &final_destination) {
            let _ = fs::remove_dir_all(&temp_path);
            return Err(Error::Io(err.to_string()));
        }
        Ok(())
    }

    fn extract_entries_to_directory(
        &self,
        destination: &Path,
        policy: &ExtractPolicy,
    ) -> Result<()> {
        let live_entries = self.validate_extract_plan(policy)?;
        let path_ids = build_path_ids(&live_entries);
        if self.should_extract_files_in_parallel(&live_entries) {
            self.extract_entries_to_directory_parallel(destination, policy, &live_entries)?;
            return Ok(());
        }
        let mut cache = HashMap::with_hasher(FastBuildHasher::default());
        for (index, entry) in live_entries.into_iter().enumerate() {
            match entry.node_kind {
                NodeKind::File => {
                    let out_path = checked_destination(destination, &entry.path)?;
                    self.extract_file_entry_to_path(
                        entry,
                        &out_path,
                        policy,
                        index as u64,
                        &path_ids,
                        &mut cache,
                    )?;
                }
                NodeKind::Symlink => {
                    if !policy.restore_symlinks {
                        continue;
                    }
                    let target = self.get_symlink_target(&entry.path)?;
                    validate_symlink(&entry.path, &target)?;
                    let out_path = checked_destination(destination, &entry.path)?;
                    if out_path.exists() && !policy.overwrite {
                        return Err(Error::SecurityLimitExceeded(format!(
                            "destination exists: {}",
                            out_path.display()
                        )));
                    }
                    if let Some(parent) = out_path.parent() {
                        fs::create_dir_all(parent).map_err(|err| Error::Io(err.to_string()))?;
                    }
                    create_symlink(&target, &out_path, policy.overwrite)?;
                }
            }
        }
        Ok(())
    }

    fn should_extract_files_in_parallel(&self, live_entries: &[&ManifestEntry]) -> bool {
        matches!(self.storage, crate::storage::StorageBackend::File(_))
            && self.pending_small_files.is_empty()
            && live_entries
                .iter()
                .filter(|entry| entry.node_kind == NodeKind::File)
                .count()
                >= 256
            && std::thread::available_parallelism()
                .map(|count| count.get() > 1)
                .unwrap_or(false)
    }

    fn extract_entries_to_directory_parallel(
        &self,
        destination: &Path,
        policy: &ExtractPolicy,
        live_entries: &[&ManifestEntry],
    ) -> Result<()> {
        let file_entries: Vec<_> = live_entries
            .iter()
            .copied()
            .filter(|entry| entry.node_kind == NodeKind::File)
            .collect();
        let path_ids = build_path_ids(&file_entries);
        let workers = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1)
            .clamp(1, 4)
            .min(file_entries.len().max(1));
        let chunk_size = file_entries.len().div_ceil(workers);

        let parallel_result = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for chunk in file_entries.chunks(chunk_size) {
                let worker = self.clone();
                let path_ids = &path_ids;
                handles.push(scope.spawn(move || {
                    let mut cache = HashMap::with_hasher(FastBuildHasher::default());
                    for entry in chunk {
                        let out_path = checked_destination(destination, &entry.path)?;
                        worker.extract_file_entry_to_path(
                            entry,
                            &out_path,
                            policy,
                            path_id_for(entry, path_ids)?,
                            path_ids,
                            &mut cache,
                        )?;
                    }
                    Ok(())
                }));
            }

            for handle in handles {
                match handle.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => return Err(err),
                    Err(_) => {
                        return Err(Error::Io("parallel extraction worker panicked".to_string()))
                    }
                }
            }
            Ok(())
        });
        parallel_result?;

        for entry in live_entries
            .iter()
            .copied()
            .filter(|entry| entry.node_kind == NodeKind::Symlink)
        {
            if !policy.restore_symlinks {
                continue;
            }
            let target = self.get_symlink_target(&entry.path)?;
            validate_symlink(&entry.path, &target)?;
            let out_path = checked_destination(destination, &entry.path)?;
            if out_path.exists() && !policy.overwrite {
                return Err(Error::SecurityLimitExceeded(format!(
                    "destination exists: {}",
                    out_path.display()
                )));
            }
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).map_err(|err| Error::Io(err.to_string()))?;
            }
            create_symlink(&target, &out_path, policy.overwrite)?;
        }

        Ok(())
    }

    fn validate_extract_plan(&self, policy: &ExtractPolicy) -> Result<Vec<&ManifestEntry>> {
        let live_entries: Vec<_> = self
            .manifest
            .values()
            .filter(|entry| !entry.deleted)
            .collect();

        if live_entries.len() > policy.max_files {
            return Err(Error::SecurityLimitExceeded(format!(
                "node count {} exceeds limit {}",
                live_entries.len(),
                policy.max_files
            )));
        }

        let mut total = 0u64;
        for entry in &live_entries {
            match entry.node_kind {
                NodeKind::File => {
                    if entry.len > policy.max_file_bytes {
                        return Err(Error::SecurityLimitExceeded(format!(
                            "{} is {} bytes, limit is {}",
                            entry.path, entry.len, policy.max_file_bytes
                        )));
                    }
                    total = total.checked_add(entry.len).ok_or_else(|| {
                        Error::SecurityLimitExceeded("total extracted size overflow".to_string())
                    })?;
                    if total > policy.max_total_bytes {
                        return Err(Error::SecurityLimitExceeded(format!(
                            "total extracted bytes {total} exceeds limit {}",
                            policy.max_total_bytes
                        )));
                    }
                }
                NodeKind::Symlink => {
                    if policy.restore_symlinks {
                        let target = self.get_symlink_target(&entry.path)?;
                        validate_symlink(&entry.path, &target)?;
                    }
                }
            }
        }

        Ok(live_entries)
    }

    fn extract_file_entry_to_path(
        &self,
        entry: &ManifestEntry,
        out_path: &Path,
        policy: &ExtractPolicy,
        path_id: u64,
        path_ids: &PathIds<'_>,
        cache: &mut DecodedSegmentCache,
    ) -> Result<()> {
        let parent = out_path
            .parent()
            .ok_or_else(|| Error::InvalidPath(entry.path.clone()))?;
        fs::create_dir_all(parent).map_err(|err| Error::Io(err.to_string()))?;

        if !policy.overwrite {
            let mut out = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out_path)
            {
                Ok(file) => file,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(Error::SecurityLimitExceeded(format!(
                        "destination exists: {}",
                        out_path.display()
                    )));
                }
                Err(err) => return Err(Error::Io(err.to_string())),
            };
            if let Err(err) =
                self.write_file_entry_cached(entry, path_id, path_ids, &mut out, cache)
            {
                let _ = fs::remove_file(out_path);
                return Err(err);
            }
            drop(out);
            restore_permissions(out_path, entry.permissions, policy)?;
            return Ok(());
        }

        if !out_path.exists() {
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out_path)
                .map_err(|err| Error::Io(err.to_string()))?;
            if let Err(err) =
                self.write_file_entry_cached(entry, path_id, path_ids, &mut out, cache)
            {
                let _ = fs::remove_file(out_path);
                return Err(err);
            }
            drop(out);
            restore_permissions(out_path, entry.permissions, policy)?;
            return Ok(());
        }

        let (temp_path, mut temp_file) = create_temp_file(parent, path_id)?;
        let write_result =
            self.write_file_entry_cached(entry, path_id, path_ids, &mut temp_file, cache);
        if let Err(err) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }
        drop(temp_file);

        if policy.overwrite && out_path.exists() {
            if let Err(err) = fs::remove_file(out_path) {
                let _ = fs::remove_file(&temp_path);
                return Err(Error::Io(err.to_string()));
            }
        }
        if let Err(err) = move_file(&temp_path, out_path) {
            let _ = fs::remove_file(&temp_path);
            return Err(Error::Io(err.to_string()));
        }
        restore_permissions(out_path, entry.permissions, policy)?;
        Ok(())
    }

    fn write_file_entry_cached(
        &self,
        entry: &ManifestEntry,
        path_id: u64,
        path_ids: &PathIds<'_>,
        writer: &mut impl Write,
        cache: &mut DecodedSegmentCache,
    ) -> Result<()> {
        if let Some(pending) = self.pending_small_files.get(&entry.path) {
            if pending.data.len() as u64 != entry.len {
                return Err(Error::CorruptRecord);
            }
            writer
                .write_all(&pending.data)
                .map_err(|err| Error::Io(err.to_string()))?;
            return Ok(());
        }

        if entry.chunks.is_empty() {
            return Err(Error::CorruptRecord);
        }

        let mut written = 0u64;
        if entry.chunks.len() == 1 {
            let chunk = &entry.chunks[0];
            let decoded = self.read_cached_chunk(
                path_id,
                path_ids,
                chunk.record_offset,
                chunk.file_offset,
                cache,
            )?;
            writer
                .write_all(&decoded)
                .map_err(|err| Error::Io(err.to_string()))?;
            written += decoded.len() as u64;
        } else {
            let mut chunks = entry.chunks.clone();
            chunks.sort_by_key(|chunk| chunk.file_offset);
            for chunk in chunks {
                let decoded = self.read_cached_chunk(
                    path_id,
                    path_ids,
                    chunk.record_offset,
                    chunk.file_offset,
                    cache,
                )?;
                writer
                    .write_all(&decoded)
                    .map_err(|err| Error::Io(err.to_string()))?;
                written += decoded.len() as u64;
            }
        }

        if written != entry.len {
            return Err(Error::CorruptRecord);
        }
        Ok(())
    }

    fn read_file_entry_cached(
        &self,
        entry: &ManifestEntry,
        path_id: u64,
        path_ids: &PathIds<'_>,
        cache: &mut DecodedSegmentCache,
    ) -> Result<Vec<u8>> {
        if let Some(pending) = self.pending_small_files.get(&entry.path) {
            return Ok(pending.data.clone());
        }

        if entry.chunks.is_empty() {
            return Err(Error::CorruptRecord);
        }

        if entry.chunks.len() == 1 {
            let chunk = &entry.chunks[0];
            return self.read_cached_chunk(
                path_id,
                path_ids,
                chunk.record_offset,
                chunk.file_offset,
                cache,
            );
        }

        let mut out = Vec::with_capacity(entry.len as usize);
        let mut chunks = entry.chunks.clone();
        chunks.sort_by_key(|chunk| chunk.file_offset);
        for chunk in chunks {
            let decoded = self.read_cached_chunk(
                path_id,
                path_ids,
                chunk.record_offset,
                chunk.file_offset,
                cache,
            )?;
            out.extend_from_slice(&decoded);
        }
        Ok(out)
    }

    fn read_cached_chunk(
        &self,
        path_id: u64,
        path_ids: &PathIds<'_>,
        record_offset: u64,
        file_offset: u64,
        cache: &mut DecodedSegmentCache,
    ) -> Result<Vec<u8>> {
        if let std::collections::hash_map::Entry::Vacant(entry) = cache.entry(record_offset) {
            let record = self.read_record(record_offset)?;
            let mut by_chunk =
                Vec::with_capacity(file_segment_chunk_count(&record.payload).unwrap_or(0));
            for_each_file_segment_chunk_trusted_toc(&record.payload, |item| {
                let Some(decoded_path_id) = path_ids.get(item.path).copied() else {
                    return Err(Error::CorruptRecord);
                };
                by_chunk.push((
                    chunk_key(decoded_path_id, item.file_offset),
                    item.data.to_vec(),
                ));
                Ok(())
            })?;
            by_chunk.sort_unstable_by_key(|(key, _)| *key);
            entry.insert(by_chunk);
        }
        let Some(decoded) = cache.get_mut(&record_offset) else {
            return Err(Error::CorruptRecord);
        };
        let key = chunk_key(path_id, file_offset);
        let Ok(index) = decoded.binary_search_by_key(&key, |(key, _)| *key) else {
            return Err(Error::CorruptRecord);
        };
        Ok(std::mem::take(&mut decoded[index].1))
    }
}

fn chunk_key(path_id: u64, file_offset: u64) -> u128 {
    ((path_id as u128) << 64) | file_offset as u128
}

fn checked_destination(root: &Path, logical_path: &str) -> Result<PathBuf> {
    canonicalize_stored_path(logical_path, false)?;
    let relative = logical_path.trim_start_matches('/');
    let mut out = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => out.push(part),
            _ => return Err(Error::InvalidPath(logical_path.to_string())),
        }
    }
    if !out.starts_with(root) {
        return Err(Error::SecurityLimitExceeded(
            "extraction destination escaped root".to_string(),
        ));
    }
    Ok(out)
}

fn build_path_ids<'a>(entries: &[&'a ManifestEntry]) -> PathIds<'a> {
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.path.as_str(), index as u64))
        .collect::<HashMap<_, _, FastBuildHasher>>()
}

fn path_id_for(entry: &ManifestEntry, path_ids: &PathIds<'_>) -> Result<u64> {
    path_ids
        .get(entry.path.as_str())
        .copied()
        .ok_or(Error::CorruptRecord)
}

fn create_temp_file(parent: &Path, index: u64) -> Result<(PathBuf, File)> {
    let process_id = std::process::id();
    for attempt in 0..1000u64 {
        let temp_path = parent.join(format!(
            ".lockbox-extract-{process_id}-{index}-{attempt}.tmp"
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(Error::Io(err.to_string())),
        }
    }
    Err(Error::Io(
        "unable to create unique extraction temporary file".to_string(),
    ))
}

fn create_temp_directory(parent: &Path) -> Result<(PathBuf, PathBuf)> {
    let process_id = std::process::id();
    for attempt in 0..1000u64 {
        let temp_path = parent.join(format!(".lockbox-extract-{process_id}-{attempt}.tmpdir"));
        match fs::create_dir(&temp_path) {
            Ok(()) => {
                let canonical = temp_path
                    .canonicalize()
                    .map_err(|err| Error::Io(err.to_string()))?;
                return Ok((temp_path, canonical));
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(Error::Io(err.to_string())),
        }
    }
    Err(Error::Io(
        "unable to create unique extraction temporary directory".to_string(),
    ))
}

fn move_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    match fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(err) if is_cross_device_error(&err) => {
            fs::copy(source, destination)?;
            fs::remove_file(source)
        }
        Err(err) => Err(err),
    }
}

fn move_directory(source: &Path, destination: &Path) -> std::io::Result<()> {
    match fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(err) if is_cross_device_error(&err) => {
            copy_directory_recursive(source, destination)?;
            fs::remove_dir_all(source)
        }
        Err(err) => Err(err),
    }
}

fn copy_directory_recursive(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_directory_recursive(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)?;
        } else if file_type.is_symlink() {
            copy_symlink(&source_path, &destination_path)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_cross_device_error(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::EXDEV)
}

#[cfg(windows)]
fn is_cross_device_error(err: &std::io::Error) -> bool {
    const ERROR_NOT_SAME_DEVICE: i32 = 17;
    err.raw_os_error() == Some(ERROR_NOT_SAME_DEVICE)
}

#[cfg(not(any(unix, windows)))]
fn is_cross_device_error(_err: &std::io::Error) -> bool {
    false
}

#[cfg(unix)]
fn copy_symlink(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(fs::read_link(source)?, destination)
}

#[cfg(windows)]
fn copy_symlink(source: &Path, destination: &Path) -> std::io::Result<()> {
    let target = fs::read_link(source)?;
    if source.is_dir() {
        std::os::windows::fs::symlink_dir(target, destination)
    } else {
        std::os::windows::fs::symlink_file(target, destination)
    }
}

#[cfg(not(any(unix, windows)))]
fn copy_symlink(_source: &Path, _destination: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "copying symlinks is not supported on this platform",
    ))
}

#[cfg(unix)]
fn restore_permissions(path: &Path, permissions: u32, policy: &ExtractPolicy) -> Result<()> {
    if policy.restore_permissions {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(permissions))
            .map_err(|err| Error::Io(err.to_string()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restore_permissions(_path: &Path, _permissions: u32, _policy: &ExtractPolicy) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &str, path: &Path, overwrite: bool) -> Result<()> {
    if overwrite && path.exists() {
        fs::remove_file(path).map_err(|err| Error::Io(err.to_string()))?;
    }
    std::os::unix::fs::symlink(target.trim_start_matches('/'), path)
        .map_err(|err| Error::Io(err.to_string()))
}

#[cfg(windows)]
fn create_symlink(target: &str, path: &Path, overwrite: bool) -> Result<()> {
    if overwrite && path.exists() {
        fs::remove_file(path).map_err(|err| Error::Io(err.to_string()))?;
    }
    std::os::windows::fs::symlink_file(target.trim_start_matches('/'), path)
        .map_err(|err| Error::Io(err.to_string()))
}

#[cfg(not(any(unix, windows)))]
fn create_symlink(_target: &str, _path: &Path, _overwrite: bool) -> Result<()> {
    Err(Error::SecurityLimitExceeded(
        "symlink extraction is not supported on this platform".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_directory_recursive_copies_nested_files() {
        let root =
            std::env::temp_dir().join(format!("lockbox-copy-dir-test-{}", std::process::id()));
        let source = root.join("source");
        let destination = root.join("destination");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("nested/file.txt"), b"content").unwrap();

        copy_directory_recursive(&source, &destination).unwrap();

        assert_eq!(
            fs::read(destination.join("nested/file.txt")).unwrap(),
            b"content"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
