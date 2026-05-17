use super::Lockbox;
use crate::file_format::read_header;
use crate::key_directory::{
    best_key_directory, encode_key_directory, read_key_directory, read_key_directory_backup,
    scan_key_directories,
};
use crate::key_slot::{next_key_slot_id, random_content_key, random_salt, KeySlot, KeySlotInfo};
use crate::key_wrap::{MlKemKeyPair, MlKemRecipientKey};
use crate::lockbox_id::LockboxId;
use crate::secret_vec::{SecretString, SecretVec};
use crate::storage::{Storage, StorageBackend};
use crate::{Error, LockboxEntryKind, LockboxOptions, Result};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub struct UnlockedContentKey {
    pub lockbox_id: LockboxId,
    key: SecretVec,
}

#[allow(clippy::large_enum_variant)]
pub enum LockboxCreate<'a> {
    RawKey(Vec<u8>),
    Password(&'a SecretString),
    RecipientKey(MlKemRecipientKey),
}

#[allow(clippy::large_enum_variant)]
pub enum LockboxUnlock<'a> {
    RawKey(Vec<u8>),
    Password(&'a SecretString),
    RecipientKey(MlKemKeyPair),
}

impl UnlockedContentKey {
    pub fn with_key<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        Ok(self.key.with_bytes(f)?)
    }

    pub fn open_bytes(self, bytes: Vec<u8>) -> Result<Lockbox> {
        Lockbox::open_storage_with_secret_key(
            StorageBackend::memory(bytes),
            self.key,
            LockboxOptions::default(),
        )
    }

    pub fn open_path(self, path: impl AsRef<Path>) -> Result<Lockbox> {
        Lockbox::open_path_with_secret_key_options(path, self.key, LockboxOptions::default())
    }
}

impl Lockbox {
    pub fn create_file(path: impl AsRef<Path>, method: LockboxCreate<'_>) -> Result<Self> {
        let mut lockbox = match method {
            LockboxCreate::RawKey(key) => Self::create_path(path, key)?,
            LockboxCreate::Password(password) => {
                let content_key = random_content_key()?;
                let mut lockbox = Self::create_path(path, content_key)?;
                lockbox.add_password_slot(password)?;
                lockbox
            }
            LockboxCreate::RecipientKey(recipient) => {
                let content_key = random_content_key()?;
                let mut lockbox = Self::create_path(path, content_key)?;
                lockbox.add_recipient_key(&recipient)?;
                lockbox
            }
        };
        lockbox.commit()?;
        Ok(lockbox)
    }

    pub fn open_file(path: impl AsRef<Path>, method: LockboxUnlock<'_>) -> Result<Self> {
        let path = path.as_ref();
        match method {
            LockboxUnlock::RawKey(key) => Self::open_path(path, key),
            LockboxUnlock::Password(password) => {
                let unlocked = Self::unlock_path_with_password(path, password)?;
                unlocked.open_path(path)
            }
            LockboxUnlock::RecipientKey(recipient) => {
                let unlocked = Self::unlock_path_with_recipient(path, &recipient)?;
                unlocked.open_path(path)
            }
        }
    }

    pub fn read_lockbox_id_path(path: impl AsRef<Path>) -> Result<LockboxId> {
        let storage = StorageBackend::file(path)?;
        let header = storage.read_at(0, crate::constants::HEADER_LEN)?;
        crate::header::read_lockbox_id(&header)
    }

    pub fn create_with_password(password: &SecretString) -> Result<Self> {
        let content_key = random_content_key()?;
        let mut lockbox = Self::create(content_key);
        lockbox.add_password_slot(password)?;
        Ok(lockbox)
    }

    pub fn open_with_password(bytes: Vec<u8>, password: &SecretString) -> Result<Self> {
        let unlocked = Self::unlock_with_password(&bytes, password)?;
        unlocked.open_bytes(bytes)
    }

    pub fn unlock_with_password(
        bytes: &[u8],
        password: &SecretString,
    ) -> Result<UnlockedContentKey> {
        for directory in key_directories_from_bytes(bytes)? {
            for slot in directory.slots {
                let Ok(key) = slot.try_password(password) else {
                    continue;
                };
                return Ok(UnlockedContentKey {
                    lockbox_id: directory.lockbox_id,
                    key: SecretVec::try_from_vec(key)?,
                });
            }
        }
        Err(Error::InvalidKey)
    }

    pub fn unlock_path_with_password(
        path: impl AsRef<Path>,
        password: &SecretString,
    ) -> Result<UnlockedContentKey> {
        let storage = StorageBackend::file(path)?;
        for directory in key_directories_from_storage(&storage)? {
            for slot in directory.slots {
                let Ok(key) = slot.try_password(password) else {
                    continue;
                };
                return Ok(UnlockedContentKey {
                    lockbox_id: directory.lockbox_id,
                    key: SecretVec::try_from_vec(key)?,
                });
            }
        }
        Err(Error::InvalidKey)
    }

    pub fn unlock_key_directory_backup_with_password(
        bytes: &[u8],
        password: &SecretString,
    ) -> Result<UnlockedContentKey> {
        let directory = read_key_directory_backup(bytes)?;
        for slot in directory.slots {
            let Ok(key) = slot.try_password(password) else {
                continue;
            };
            return Ok(UnlockedContentKey {
                lockbox_id: directory.lockbox_id,
                key: SecretVec::try_from_vec(key)?,
            });
        }
        Err(Error::InvalidKey)
    }

    pub fn create_with_recipient(recipient: &MlKemKeyPair) -> Result<Self> {
        Self::create_with_recipient_key(&recipient.recipient_key())
    }

    pub fn create_with_recipient_key(recipient: &MlKemRecipientKey) -> Result<Self> {
        let content_key = random_content_key()?;
        let mut lockbox = Self::create(content_key);
        lockbox.add_recipient_key(recipient)?;
        Ok(lockbox)
    }

    pub fn open_with_recipient(bytes: Vec<u8>, recipient: &MlKemKeyPair) -> Result<Self> {
        let unlocked = Self::unlock_with_recipient(&bytes, recipient)?;
        unlocked.open_bytes(bytes)
    }

    pub fn unlock_with_recipient(
        bytes: &[u8],
        recipient: &MlKemKeyPair,
    ) -> Result<UnlockedContentKey> {
        for directory in key_directories_from_bytes(bytes)? {
            for slot in directory.slots {
                let Ok(key) = slot.try_ml_kem(recipient) else {
                    continue;
                };
                return Ok(UnlockedContentKey {
                    lockbox_id: directory.lockbox_id,
                    key: SecretVec::try_from_vec(key)?,
                });
            }
        }
        Err(Error::InvalidKey)
    }

    pub fn unlock_path_with_recipient(
        path: impl AsRef<Path>,
        recipient: &MlKemKeyPair,
    ) -> Result<UnlockedContentKey> {
        let storage = StorageBackend::file(path)?;
        for directory in key_directories_from_storage(&storage)? {
            for slot in directory.slots {
                let Ok(key) = slot.try_ml_kem(recipient) else {
                    continue;
                };
                return Ok(UnlockedContentKey {
                    lockbox_id: directory.lockbox_id,
                    key: SecretVec::try_from_vec(key)?,
                });
            }
        }
        Err(Error::InvalidKey)
    }

    pub fn unlock_key_directory_backup_with_recipient(
        bytes: &[u8],
        recipient: &MlKemKeyPair,
    ) -> Result<UnlockedContentKey> {
        let directory = read_key_directory_backup(bytes)?;
        for slot in directory.slots {
            let Ok(key) = slot.try_ml_kem(recipient) else {
                continue;
            };
            return Ok(UnlockedContentKey {
                lockbox_id: directory.lockbox_id,
                key: SecretVec::try_from_vec(key)?,
            });
        }
        Err(Error::InvalidKey)
    }

    pub fn add_password_slot(&mut self, password: &SecretString) -> Result<u64> {
        let id = next_key_slot_id(&self.key_slots);
        let salt = random_salt()?;
        let slot = lockbox_secure::read_access(|access| {
            access.with_bytes(&self.key, |content_key| {
                password.with_bytes_in(access, |password| {
                    KeySlot::password_bytes(id, password, salt, content_key)
                })
            })
        })???;
        self.key_slots.push(slot);
        self.mark_key_directory_dirty();
        Ok(id)
    }

    pub fn add_recipient(&mut self, recipient: &MlKemKeyPair) -> Result<u64> {
        self.add_recipient_key(&recipient.recipient_key())
    }

    pub fn add_recipient_key(&mut self, recipient: &MlKemRecipientKey) -> Result<u64> {
        let id = next_key_slot_id(&self.key_slots);
        let slot = self
            .key
            .with_bytes(|content_key| KeySlot::ml_kem_1024(id, recipient, content_key))??;
        self.key_slots.push(slot);
        self.mark_key_directory_dirty();
        Ok(id)
    }

    pub fn remove_key_slot(&mut self, id: u64) -> Result<()> {
        let before = self.key_slots.len();
        self.key_slots.retain(|slot| slot.id() != id);
        if self.key_slots.len() == before {
            return Err(Error::NotFound(format!("key slot {id}")));
        }
        self.mark_key_directory_dirty();
        Ok(())
    }

    pub fn delete_key_slot(&mut self, id: u64) -> Result<()> {
        self.remove_key_slot(id)
    }

    pub fn remove_key_slot_and_compact(&mut self, id: u64) -> Result<()> {
        let Some(index) = self.key_slots.iter().position(|slot| slot.id() == id) else {
            return Err(Error::NotFound(format!("key slot {id}")));
        };
        if self.key_slots.len() == 1 {
            return Err(Error::SecurityLimitExceeded(
                "refusing to remove the last key slot".to_string(),
            ));
        }
        let removed = self.key_slots.remove(index);
        self.mark_key_directory_dirty();
        let result = self.compact();
        if result.is_err() {
            self.key_slots.insert(index, removed);
            self.mark_key_directory_dirty();
        }
        result
    }

    pub fn delete_key_slot_and_compact(&mut self, id: u64) -> Result<()> {
        self.remove_key_slot_and_compact(id)
    }

    pub fn export_key_directory_backup(&self) -> Result<Vec<u8>> {
        encode_key_directory(
            &self.key_slots,
            self.lockbox_id,
            self.key_directory_generation,
            0,
        )
    }

    pub fn list_key_slots(&self) -> Vec<KeySlotInfo> {
        self.key_slots.iter().map(KeySlot::info).collect()
    }

    pub fn change_password(
        &mut self,
        old_password: &SecretString,
        new_password: &SecretString,
    ) -> Result<u64> {
        let mut matching_id = None;
        for slot in &self.key_slots {
            if slot.try_password(old_password).is_ok() {
                matching_id = Some(slot.id());
                break;
            }
        }
        let Some(old_id) = matching_id else {
            return Err(Error::InvalidKey);
        };
        let new_id = self.add_password_slot(new_password)?;
        self.remove_key_slot(old_id)?;
        self.compact()?;
        Ok(new_id)
    }

    pub fn compact(&mut self) -> Result<()> {
        let entries = self
            .manifest
            .values()
            .filter(|entry| !entry.deleted)
            .cloned()
            .collect::<Vec<_>>();
        let env = self.clone_all_env_values()?;
        if let Some(path) = self.storage.path().map(Path::to_path_buf) {
            return self.compact_file_backed(path, entries, env);
        }

        let key = self.key.try_clone()?;
        let mut compacted = Lockbox::create_with_secret_key_and_options(
            key,
            self.lockbox_id,
            self.compaction_options(),
        );
        self.populate_compacted(&mut compacted, entries, env)?;
        compacted.commit()?;
        *self = compacted;
        Ok(())
    }

    fn compact_file_backed(
        &mut self,
        path: PathBuf,
        entries: Vec<crate::manifest_entry::ManifestEntry>,
        env: std::collections::BTreeMap<String, crate::env_btree::EnvValue>,
    ) -> Result<()> {
        let temp_path = compact_temp_path(&path);
        let _ = fs::remove_file(&temp_path);
        let options = self.compaction_options();
        let result = (|| {
            let key = self.key.try_clone()?;
            let reopen_key = key.try_clone()?;
            let mut compacted = Lockbox::create_path_with_secret_key_and_options(
                &temp_path,
                key,
                self.lockbox_id,
                options,
            )?;
            self.populate_compacted(&mut compacted, entries, env)?;
            compacted.commit()?;
            drop(compacted);
            replace_file_with_compacted(&temp_path, &path)?;
            let reopened = Lockbox::open_path_with_secret_key_options(&path, reopen_key, options)?;
            *self = reopened;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    fn populate_compacted(
        &self,
        compacted: &mut Lockbox,
        entries: Vec<crate::manifest_entry::ManifestEntry>,
        env: std::collections::BTreeMap<String, crate::env_btree::EnvValue>,
    ) -> Result<()> {
        compacted.key_slots = self.key_slots.clone();
        compacted.key_directory_generation = self.key_directory_generation;
        compacted.dirty_key_directory = !compacted.key_slots.is_empty();

        for (name, value) in env {
            compacted.set_env_value(name, value)?;
        }

        for entry in entries {
            match entry.entry_kind() {
                LockboxEntryKind::File => {
                    let reader = FileEntryReader::new(self, &entry)?;
                    compacted.put_file_from_reader_with_permissions(
                        &entry.path,
                        reader,
                        entry.permissions,
                    )?;
                }
                LockboxEntryKind::Symlink => {
                    let target = self.get_symlink_target(&entry.path)?;
                    compacted.put_symlink(&entry.path, &target)?;
                }
            }
        }
        Ok(())
    }

    fn compaction_options(&self) -> LockboxOptions {
        LockboxOptions {
            workload_profile: self.workload_profile,
            ..LockboxOptions::default()
        }
    }
}

fn compact_temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("lockbox");
    path.with_file_name(format!(".{file_name}.compact-{}", std::process::id()))
}

fn replace_file_with_compacted(temp_path: &Path, path: &Path) -> Result<()> {
    fs::rename(temp_path, path).map_err(|err| {
        Error::Io(format!(
            "replace compacted lockbox {}: {err}",
            path.display()
        ))
    })
}

impl Lockbox {
    pub(crate) fn mark_key_directory_dirty(&mut self) {
        self.key_directory_generation = self.key_directory_generation.saturating_add(1);
        self.dirty_key_directory = true;
    }
}

struct FileEntryReader<'a> {
    lockbox: &'a Lockbox,
    entry: &'a crate::manifest_entry::ManifestEntry,
    chunks: Vec<crate::file_chunk::FileChunk>,
    next_chunk: usize,
    current: Cursor<Vec<u8>>,
    written: u64,
}

impl<'a> FileEntryReader<'a> {
    fn new(lockbox: &'a Lockbox, entry: &'a crate::manifest_entry::ManifestEntry) -> Result<Self> {
        if let Some(pending) = lockbox.pending_small_files.get(&entry.path) {
            if pending.data.len() as u64 != entry.len {
                return Err(Error::CorruptRecord);
            }
            return Ok(Self {
                lockbox,
                entry,
                chunks: Vec::new(),
                next_chunk: 0,
                current: Cursor::new(pending.data.to_vec()),
                written: 0,
            });
        }
        if entry.chunks.is_empty() {
            return Err(Error::CorruptRecord);
        }
        let mut chunks = entry.chunks.clone();
        chunks.sort_by_key(|chunk| chunk.file_offset);
        Ok(Self {
            lockbox,
            entry,
            chunks,
            next_chunk: 0,
            current: Cursor::new(Vec::new()),
            written: 0,
        })
    }
}

impl Read for FileEntryReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let read = self.current.read(out)?;
            if read != 0 {
                self.written = self.written.saturating_add(read as u64);
                return Ok(read);
            }
            if self.next_chunk >= self.chunks.len() {
                if self.written == self.entry.len {
                    return Ok(0);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "lockbox file length mismatch during compaction",
                ));
            }
            let chunk = &self.chunks[self.next_chunk];
            if chunk.file_offset != self.written {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "lockbox file chunk offset mismatch during compaction",
                ));
            }
            self.next_chunk += 1;
            let decoded = self
                .lockbox
                .read_file_chunk_frame(self.entry.len, chunk)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
            self.current = Cursor::new(decoded);
        }
    }
}

fn key_directories_from_bytes(
    bytes: &[u8],
) -> Result<Vec<crate::key_directory::DecodedKeyDirectory>> {
    let mut directories = Vec::new();
    if let Ok((_, _, key_directory_offset, lockbox_id)) = read_header(bytes) {
        if let Ok(directory) = read_key_directory(bytes, key_directory_offset, Some(lockbox_id)) {
            directories.push(directory);
        }
        directories.extend(scan_key_directories(bytes, Some(lockbox_id)));
    } else {
        directories.extend(scan_key_directories(bytes, None));
    }
    if directories.is_empty() {
        return Err(Error::CorruptHeader);
    }
    let Some(best) = best_key_directory(directories.clone()) else {
        return Err(Error::CorruptHeader);
    };
    directories.sort_by_key(|directory| {
        (
            std::cmp::Reverse(directory.lockbox_id == best.lockbox_id),
            std::cmp::Reverse(directory.generation),
            directory.copy_index,
        )
    });
    Ok(directories)
}

fn key_directories_from_storage(
    storage: &StorageBackend,
) -> Result<Vec<crate::key_directory::DecodedKeyDirectory>> {
    let header = storage.read_at(0, crate::constants::HEADER_LEN)?;
    let mut directories = Vec::new();
    if let Ok((_, _, key_directory_offset, lockbox_id)) = read_header(&header) {
        if let Ok(directory) = crate::key_directory::read_key_directory_via_page_cache(
            storage,
            key_directory_offset,
            Some(lockbox_id),
        ) {
            directories.push(directory);
        }
        if directories.is_empty() {
            let bytes = storage.read_all()?;
            directories.extend(scan_key_directories(&bytes, Some(lockbox_id)));
        }
    } else {
        let bytes = storage.read_all()?;
        directories.extend(scan_key_directories(&bytes, None));
    }
    if directories.is_empty() {
        return Err(Error::CorruptHeader);
    }
    let Some(best) = best_key_directory(directories.clone()) else {
        return Err(Error::CorruptHeader);
    };
    directories.sort_by_key(|directory| {
        (
            std::cmp::Reverse(directory.lockbox_id == best.lockbox_id),
            std::cmp::Reverse(directory.generation),
            directory.copy_index,
        )
    });
    Ok(directories)
}
