use super::Lockbox;
use crate::format::read_header;
use crate::key_directory::{
    best_key_directory, encode_key_directory, read_key_directory, read_key_directory_backup,
    scan_key_directories,
};
use crate::key_slot::{next_key_slot_id, random_content_key, random_salt, KeySlot, KeySlotInfo};
use crate::key_wrap::{MlKemKeyPair, MlKemRecipientKey};
use crate::lockbox_id::LockboxId;
use crate::secret_bytes::SecretBytes;
use crate::storage::{Storage, StorageBackend};
use crate::{EntryKind, Error, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockedContentKey {
    pub lockbox_id: LockboxId,
    key: SecretBytes,
}

#[allow(clippy::large_enum_variant)]
pub enum LockboxCreate {
    RawKey(Vec<u8>),
    Password(Vec<u8>),
    RecipientKey(MlKemRecipientKey),
    RecipientKeyFile(PathBuf),
}

#[allow(clippy::large_enum_variant)]
pub enum LockboxUnlock {
    RawKey(Vec<u8>),
    Password(Vec<u8>),
    RecipientKey(MlKemKeyPair),
    RecipientKeyFile(PathBuf),
}

impl UnlockedContentKey {
    pub fn key(&self) -> &[u8] {
        self.key.expose()
    }

    pub fn into_key_bytes(self) -> Vec<u8> {
        self.key.clone_exposed()
    }
}

impl Lockbox {
    pub fn create_file(path: impl AsRef<Path>, method: LockboxCreate) -> Result<Self> {
        let mut lockbox = match method {
            LockboxCreate::RawKey(key) => Self::create_path(path, key)?,
            LockboxCreate::Password(password) => {
                let content_key = random_content_key()?;
                let mut lockbox = Self::create_path(path, content_key)?;
                lockbox.add_password_slot(&password)?;
                lockbox
            }
            LockboxCreate::RecipientKey(recipient) => {
                let content_key = random_content_key()?;
                let mut lockbox = Self::create_path(path, content_key)?;
                lockbox.add_recipient_key(&recipient)?;
                lockbox
            }
            LockboxCreate::RecipientKeyFile(path_to_key) => {
                let recipient = MlKemRecipientKey::from_bytes(&read_hex_file(path_to_key)?)?;
                let content_key = random_content_key()?;
                let mut lockbox = Self::create_path(path, content_key)?;
                lockbox.add_recipient_key(&recipient)?;
                lockbox
            }
        };
        lockbox.commit()?;
        Ok(lockbox)
    }

    pub fn open_file(path: impl AsRef<Path>, method: LockboxUnlock) -> Result<Self> {
        let path = path.as_ref();
        match method {
            LockboxUnlock::RawKey(key) => Self::open_path(path, key),
            LockboxUnlock::Password(password) => {
                let unlocked = Self::unlock_path_with_password(path, &password)?;
                Self::open_path(path, unlocked.key())
            }
            LockboxUnlock::RecipientKey(recipient) => {
                let unlocked = Self::unlock_path_with_recipient(path, &recipient)?;
                Self::open_path(path, unlocked.key())
            }
            LockboxUnlock::RecipientKeyFile(path_to_key) => {
                let keypair = MlKemKeyPair::from_seed_bytes(&read_hex_file(path_to_key)?)?;
                let unlocked = Self::unlock_path_with_recipient(path, &keypair)?;
                Self::open_path(path, unlocked.key())
            }
        }
    }

    pub fn read_lockbox_id_path(path: impl AsRef<Path>) -> Result<LockboxId> {
        let storage = StorageBackend::file(path)?;
        let header = storage.read_at(0, crate::constants::HEADER_LEN)?;
        crate::header::read_lockbox_id(&header)
    }

    pub fn create_with_password(password: &[u8]) -> Result<Self> {
        let content_key = random_content_key()?;
        let mut lockbox = Self::create(content_key);
        lockbox.add_password_slot(password)?;
        Ok(lockbox)
    }

    pub fn open_with_password(bytes: Vec<u8>, password: &[u8]) -> Result<Self> {
        let unlocked = Self::unlock_with_password(&bytes, password)?;
        Self::open(bytes, unlocked.key())
    }

    pub fn unlock_with_password(bytes: &[u8], password: &[u8]) -> Result<UnlockedContentKey> {
        for directory in key_directories_from_bytes(bytes)? {
            for slot in directory.slots {
                let Ok(key) = slot.try_password(password) else {
                    continue;
                };
                return Ok(UnlockedContentKey {
                    lockbox_id: directory.lockbox_id,
                    key: SecretBytes::new(key),
                });
            }
        }
        Err(Error::InvalidKey)
    }

    pub fn unlock_path_with_password(
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<UnlockedContentKey> {
        let storage = StorageBackend::file(path)?;
        for directory in key_directories_from_storage(&storage)? {
            for slot in directory.slots {
                let Ok(key) = slot.try_password(password) else {
                    continue;
                };
                return Ok(UnlockedContentKey {
                    lockbox_id: directory.lockbox_id,
                    key: SecretBytes::new(key),
                });
            }
        }
        Err(Error::InvalidKey)
    }

    pub fn unlock_key_directory_backup_with_password(
        bytes: &[u8],
        password: &[u8],
    ) -> Result<UnlockedContentKey> {
        let directory = read_key_directory_backup(bytes)?;
        for slot in directory.slots {
            let Ok(key) = slot.try_password(password) else {
                continue;
            };
            return Ok(UnlockedContentKey {
                lockbox_id: directory.lockbox_id,
                key: SecretBytes::new(key),
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
        Self::open(bytes, unlocked.key())
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
                    key: SecretBytes::new(key),
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
                    key: SecretBytes::new(key),
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
                key: SecretBytes::new(key),
            });
        }
        Err(Error::InvalidKey)
    }

    pub fn add_password_slot(&mut self, password: &[u8]) -> Result<u64> {
        let id = next_key_slot_id(&self.key_slots);
        let slot = KeySlot::password(id, password, random_salt()?, self.key.expose())?;
        self.key_slots.push(slot);
        Ok(id)
    }

    pub fn add_recipient(&mut self, recipient: &MlKemKeyPair) -> Result<u64> {
        self.add_recipient_key(&recipient.recipient_key())
    }

    pub fn add_recipient_key(&mut self, recipient: &MlKemRecipientKey) -> Result<u64> {
        let id = next_key_slot_id(&self.key_slots);
        let slot = KeySlot::ml_kem_1024(id, recipient, self.key.expose())?;
        self.key_slots.push(slot);
        Ok(id)
    }

    pub fn remove_key_slot(&mut self, id: u64) -> Result<()> {
        let before = self.key_slots.len();
        self.key_slots.retain(|slot| slot.id() != id);
        if self.key_slots.len() == before {
            return Err(Error::NotFound(format!("key slot {id}")));
        }
        Ok(())
    }

    pub fn delete_key_slot(&mut self, id: u64) -> Result<()> {
        self.remove_key_slot(id)
    }

    pub fn remove_key_slot_and_compact(&mut self, id: u64) -> Result<()> {
        let mut compacted_source = self.clone();
        compacted_source.remove_key_slot(id)?;
        if compacted_source.key_slots.is_empty() {
            return Err(Error::SecurityLimitExceeded(
                "refusing to remove the last key slot".to_string(),
            ));
        }
        compacted_source.compact()?;
        *self = compacted_source;
        Ok(())
    }

    pub fn delete_key_slot_and_compact(&mut self, id: u64) -> Result<()> {
        self.remove_key_slot_and_compact(id)
    }

    pub fn export_key_directory_backup(&self) -> Result<Vec<u8>> {
        encode_key_directory(&self.key_slots, self.lockbox_id, self.sequence, 0)
    }

    pub fn list_key_slots(&self) -> Vec<KeySlotInfo> {
        self.key_slots.iter().map(KeySlot::info).collect()
    }

    pub fn change_password(&mut self, old_password: &[u8], new_password: &[u8]) -> Result<u64> {
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
        let original_storage = self.storage.clone();
        let entries = self
            .manifest
            .values()
            .filter(|entry| !entry.deleted)
            .cloned()
            .collect::<Vec<_>>();
        let env = self.get_all_env();
        let key_slots = self.key_slots.clone();
        let mut compacted = Lockbox::create_with_lockbox_id(self.key.expose(), self.lockbox_id);
        compacted.key_slots = key_slots;

        for (name, value) in env {
            compacted.set_env(&name, &value)?;
        }

        for entry in entries {
            match entry.entry_kind() {
                EntryKind::File => {
                    let mut data = Vec::new();
                    self.write_file_to(&entry.path, &mut data)?;
                    compacted.put_file_with_permissions(&entry.path, &data, entry.permissions)?;
                }
                EntryKind::Symlink => {
                    let Some(target) = entry.symlink_target.as_deref() else {
                        return Err(Error::CorruptRecord);
                    };
                    compacted.put_symlink(&entry.path, target)?;
                }
            }
        }

        compacted.commit()?;
        let compacted_bytes = compacted.bytes()?;
        compacted.storage = original_storage;
        compacted.storage.replace_all(&compacted_bytes)?;
        *self = compacted;
        Ok(())
    }
}

fn read_hex_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let text = std::fs::read_to_string(path.as_ref())
        .map_err(|err| Error::Io(format!("read {}: {err}", path.as_ref().display())))?;
    decode_hex(text.trim())
}

fn decode_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::InvalidKey);
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for chunk in text.as_bytes().chunks_exact(2) {
        let hi = hex_value(chunk[0])?;
        let lo = hex_value(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidKey),
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
        if let Ok(directory) = crate::key_directory::read_key_directory_from_storage(
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
