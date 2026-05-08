use super::Lockbox;
use crate::format::read_header;
use crate::key_directory::read_key_directory;
use crate::key_slot::{next_key_slot_id, random_salt, random_vault_key, KeySlot, KeySlotInfo};
use crate::key_wrap::{MlKemKeyPair, MlKemRecipientKey};
use crate::secret_bytes::SecretBytes;
use crate::vault_id::VaultId;
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockedVaultKey {
    pub vault_id: VaultId,
    key: SecretBytes,
}

impl UnlockedVaultKey {
    pub fn key(&self) -> &[u8] {
        self.key.expose()
    }

    pub fn into_key_bytes(self) -> Vec<u8> {
        self.key.clone_exposed()
    }
}

impl Lockbox {
    pub fn create_with_password(password: &[u8]) -> Result<Self> {
        let vault_key = random_vault_key()?;
        let mut lockbox = Self::create(vault_key);
        lockbox.add_password_slot(password)?;
        Ok(lockbox)
    }

    pub fn open_with_password(bytes: Vec<u8>, password: &[u8]) -> Result<Self> {
        let unlocked = Self::unlock_with_password(&bytes, password)?;
        Self::open(bytes, unlocked.key())
    }

    pub fn unlock_with_password(bytes: &[u8], password: &[u8]) -> Result<UnlockedVaultKey> {
        let (_, _, _, vault_id) = read_header(bytes)?;
        for slot in key_slots_from_bytes(bytes)? {
            if let Ok(key) = slot.try_password(password) {
                return Ok(UnlockedVaultKey {
                    vault_id,
                    key: SecretBytes::new(key),
                });
            }
        }
        Err(Error::InvalidKey)
    }

    pub fn create_with_recipient(recipient: &MlKemKeyPair) -> Result<Self> {
        Self::create_with_recipient_key(&recipient.recipient_key())
    }

    pub fn create_with_recipient_key(recipient: &MlKemRecipientKey) -> Result<Self> {
        let vault_key = random_vault_key()?;
        let mut lockbox = Self::create(vault_key);
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
    ) -> Result<UnlockedVaultKey> {
        let (_, _, _, vault_id) = read_header(bytes)?;
        for slot in key_slots_from_bytes(bytes)? {
            if let Ok(key) = slot.try_ml_kem(recipient) {
                return Ok(UnlockedVaultKey {
                    vault_id,
                    key: SecretBytes::new(key),
                });
            }
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
        Ok(new_id)
    }
}

fn key_slots_from_bytes(bytes: &[u8]) -> Result<Vec<KeySlot>> {
    let (_, _, key_directory_offset, _) = read_header(bytes)?;
    read_key_directory(bytes, key_directory_offset)
}
