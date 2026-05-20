use super::Lockbox;
use crate::host_path::HostPath;
use crate::lockbox_path::{canonicalize_stored_path, validate_symlink_paths as validate_symlink};
use crate::node_kind::NodeKind;
use crate::toc_entry::TocEntry;
use crate::{Error, ExtractPolicy, Result};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

impl Lockbox {
    /// Extract all permitted entries into a destination directory.
    ///
    /// Returns `Error::Io` for host filesystem failures,
    /// `Error::SecurityLimitExceeded` when the extraction policy rejects the
    /// destination or size/count limits, and lockbox read errors for corrupt or
    /// missing stored entries.
    pub fn extract_to_directory(&self, destination: &Path, policy: &ExtractPolicy) -> Result<()> {
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
        let current_entries = self.validate_extract_plan(policy)?;
        if self.should_extract_files_in_parallel(&current_entries) {
            self.extract_entries_to_directory_parallel(destination, policy, &current_entries)?;
            return Ok(());
        }
        for (index, entry) in current_entries.into_iter().enumerate() {
            match entry.node_kind {
                NodeKind::File => {
                    let out_path = checked_destination(destination, &entry.path)?;
                    self.extract_file_entry_to_path(entry, &out_path, policy, index as u64)?;
                }
                NodeKind::Symlink => {
                    if !policy.restore_symlinks {
                        continue;
                    }
                    let target = self.get_symlink_target(&entry.path)?;
                    validate_symlink(entry.path.as_str(), target.as_str())?;
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
                    create_symlink(target.as_str(), &out_path, policy.overwrite)?;
                }
            }
        }
        Ok(())
    }

    fn should_extract_files_in_parallel(&self, current_entries: &[&TocEntry]) -> bool {
        matches!(self.storage, crate::storage::StorageBackend::File(_))
            && self.pending_small_files.is_empty()
            && current_entries
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
        current_entries: &[&TocEntry],
    ) -> Result<()> {
        let file_entries: Vec<_> = current_entries
            .iter()
            .copied()
            .filter(|entry| entry.node_kind == NodeKind::File)
            .enumerate()
            .collect();
        let workers = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1)
            .clamp(1, 4)
            .min(file_entries.len().max(1));
        let worker_jobs = group_parallel_extraction_jobs(file_entries, workers);

        let parallel_result = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for job in worker_jobs {
                let worker = self.try_clone()?;
                handles.push(scope.spawn(move || {
                    for (path_id, entry) in job {
                        let out_path = checked_destination(destination, &entry.path)?;
                        worker.extract_file_entry_to_path(
                            entry,
                            &out_path,
                            policy,
                            path_id as u64,
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

        for entry in current_entries
            .iter()
            .copied()
            .filter(|entry| entry.node_kind == NodeKind::Symlink)
        {
            if !policy.restore_symlinks {
                continue;
            }
            let target = self.get_symlink_target(&entry.path)?;
            validate_symlink(entry.path.as_str(), target.as_str())?;
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
            create_symlink(target.as_str(), &out_path, policy.overwrite)?;
        }

        Ok(())
    }

    fn validate_extract_plan(&self, policy: &ExtractPolicy) -> Result<Vec<&TocEntry>> {
        let current_entries: Vec<_> = self
            .toc_entries
            .values()
            .filter(|entry| !entry.deleted)
            .collect();

        if current_entries.len() > policy.max_files {
            return Err(Error::SecurityLimitExceeded(format!(
                "node count {} exceeds limit {}",
                current_entries.len(),
                policy.max_files
            )));
        }

        let mut total = 0u64;
        for entry in &current_entries {
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
                        validate_symlink(entry.path.as_str(), target.as_str())?;
                    }
                }
            }
        }

        Ok(current_entries)
    }

    fn extract_file_entry_to_path(
        &self,
        entry: &TocEntry,
        out_path: &Path,
        policy: &ExtractPolicy,
        path_id: u64,
    ) -> Result<()> {
        let parent = out_path
            .parent()
            .ok_or_else(|| Error::InvalidPath(entry.path.to_string()))?;
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
            if let Err(err) = self.write_file_entry_cached(entry, &mut out) {
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
            if let Err(err) = self.write_file_entry_cached(entry, &mut out) {
                let _ = fs::remove_file(out_path);
                return Err(err);
            }
            drop(out);
            restore_permissions(out_path, entry.permissions, policy)?;
            return Ok(());
        }

        let (temp_path, mut temp_file) = create_temp_file(parent, path_id)?;
        let write_result = self.write_file_entry_cached(entry, &mut temp_file);
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

    fn write_file_entry_cached(&self, entry: &TocEntry, writer: &mut impl Write) -> Result<()> {
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
        let mut chunks = entry.chunks.clone();
        chunks.sort_by_key(|chunk| chunk.file_offset);
        for chunk in chunks {
            if chunk.file_offset != written {
                return Err(Error::CorruptRecord);
            }
            let decoded = self.read_file_chunk_compression_frame(entry.len, &chunk)?;
            writer
                .write_all(&decoded)
                .map_err(|err| Error::Io(err.to_string()))?;
            written += decoded.len() as u64;
        }

        if written != entry.len {
            return Err(Error::CorruptRecord);
        }
        Ok(())
    }
}

fn group_parallel_extraction_jobs<'a>(
    file_entries: Vec<(usize, &'a TocEntry)>,
    workers: usize,
) -> Vec<Vec<(usize, &'a TocEntry)>> {
    let mut frame_groups: BTreeMap<u64, Vec<(usize, &'a TocEntry)>> = BTreeMap::new();
    for (path_id, entry) in file_entries {
        let frame_id = entry
            .chunks
            .first()
            .map(|chunk| chunk.compression_frame_id)
            .unwrap_or(u64::MAX);
        frame_groups
            .entry(frame_id)
            .or_default()
            .push((path_id, entry));
    }

    let mut jobs = vec![Vec::new(); workers];
    for (_, group) in frame_groups {
        let target = jobs
            .iter()
            .enumerate()
            .min_by_key(|(_, job)| job.len())
            .map(|(index, _)| index)
            .unwrap_or(0);
        jobs[target].extend(group);
    }
    jobs.into_iter().filter(|job| !job.is_empty()).collect()
}

fn checked_destination(root: &Path, lockbox_path: &str) -> Result<PathBuf> {
    canonicalize_stored_path(lockbox_path, false)?;
    let relative = lockbox_path.trim_start_matches('/');
    let mut out = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => out.push(part),
            _ => return Err(Error::InvalidPath(lockbox_path.to_string())),
        }
    }
    if !out.starts_with(root) {
        return Err(Error::SecurityLimitExceeded(
            "extraction destination escaped root".to_string(),
        ));
    }
    Ok(out)
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
