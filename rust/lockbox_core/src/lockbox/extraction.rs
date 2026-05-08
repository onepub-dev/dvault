use super::Lockbox;
use crate::node_kind::NodeKind;
use crate::security::{canonicalize_stored_path, validate_symlink};
use crate::{Error, ExtractPolicy, ExtractedFile, ExtractedNode, ExtractedSymlink, Result};
use std::fs::{self, OpenOptions};
use std::path::{Component, Path, PathBuf};

impl Lockbox {
    pub fn extract_all(&self, policy: &ExtractPolicy) -> Result<Vec<ExtractedFile>> {
        let live_entries: Vec<_> = self
            .manifest
            .values()
            .filter(|entry| !entry.deleted && entry.node_kind == NodeKind::File)
            .cloned()
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
        for entry in live_entries {
            canonicalize_stored_path(&entry.path, false)?;
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
            let bytes = self.get_file(&entry.path)?;
            if bytes.len() as u64 != entry.len {
                return Err(Error::CorruptRecord);
            }
            extracted.push(ExtractedFile {
                path: entry.path,
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
            .cloned()
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
        for entry in live_entries {
            canonicalize_stored_path(&entry.path, false)?;
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
                    let bytes = self.get_file(&entry.path)?;
                    extracted.push(ExtractedNode::File(ExtractedFile {
                        path: entry.path,
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
                        path: entry.path,
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
        let destination = destination.as_ref();
        fs::create_dir_all(destination).map_err(|err| Error::Io(err.to_string()))?;
        let destination = destination
            .canonicalize()
            .map_err(|err| Error::Io(err.to_string()))?;

        for node in self.extract_all_nodes(policy)? {
            match node {
                ExtractedNode::File(file) => {
                    let out_path = checked_destination(&destination, &file.path)?;
                    if let Some(parent) = out_path.parent() {
                        fs::create_dir_all(parent).map_err(|err| Error::Io(err.to_string()))?;
                    }
                    let mut options = OpenOptions::new();
                    options
                        .write(true)
                        .create_new(!policy.overwrite)
                        .create(policy.overwrite)
                        .truncate(policy.overwrite);
                    let mut out = options
                        .open(&out_path)
                        .map_err(|err| Error::Io(err.to_string()))?;
                    std::io::Write::write_all(&mut out, &file.bytes)
                        .map_err(|err| Error::Io(err.to_string()))?;
                    restore_permissions(&out_path, file.permissions, policy)?;
                }
                ExtractedNode::Symlink(link) => {
                    if !policy.restore_symlinks {
                        continue;
                    }
                    let out_path = checked_destination(&destination, &link.path)?;
                    if out_path.exists() && !policy.overwrite {
                        return Err(Error::SecurityLimitExceeded(format!(
                            "destination exists: {}",
                            out_path.display()
                        )));
                    }
                    if let Some(parent) = out_path.parent() {
                        fs::create_dir_all(parent).map_err(|err| Error::Io(err.to_string()))?;
                    }
                    create_symlink(&link.target, &out_path, policy.overwrite)?;
                }
            }
        }
        Ok(())
    }
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
