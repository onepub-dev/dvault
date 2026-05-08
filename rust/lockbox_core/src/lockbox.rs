use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::constants::HEADER_LEN;
use crate::format::{decode_manifest, read_header, read_record, write_header};
use crate::free_slot::FreeSlot;
use crate::key_directory::read_key_directory;
use crate::key_slot::KeySlot;
use crate::manifest_entry::ManifestEntry;
use crate::record::RecordKind;
use crate::secret_bytes::SecretBytes;
use crate::vault_id::VaultId;
use crate::{Error, Result};

mod commit;
mod env;
mod extraction;
mod files;
mod key_management;
mod listing;
mod mutation;
mod recovery;
mod symlinks;

pub use key_management::UnlockedVaultKey;

#[derive(Debug, Clone)]
pub struct Lockbox {
    bytes: Vec<u8>,
    key: SecretBytes,
    sequence: u64,
    manifest_offset: u64,
    key_directory_offset: u64,
    vault_id: VaultId,
    key_slots: Vec<KeySlot>,
    manifest: BTreeMap<String, ManifestEntry>,
    env_vars: RefCell<Option<BTreeMap<String, String>>>,
    free_slots: Vec<FreeSlot>,
    needs_packing: bool,
}

impl Lockbox {
    pub fn create(key: impl AsRef<[u8]>) -> Self {
        Self::create_with_vault_id(
            key,
            VaultId::new_random().expect("system random source failed"),
        )
    }

    pub fn create_with_vault_id(key: impl AsRef<[u8]>, vault_id: VaultId) -> Self {
        let key = SecretBytes::new(key.as_ref().to_vec());
        let mut bytes = vec![0; HEADER_LEN];
        write_header(&mut bytes, 0, 0, 0, vault_id);
        Self {
            bytes,
            key,
            sequence: 0,
            manifest_offset: 0,
            key_directory_offset: 0,
            vault_id,
            key_slots: Vec::new(),
            manifest: BTreeMap::new(),
            env_vars: RefCell::new(Some(BTreeMap::new())),
            free_slots: Vec::new(),
            needs_packing: false,
        }
    }

    pub fn open(bytes: Vec<u8>, key: impl AsRef<[u8]>) -> Result<Self> {
        let key = SecretBytes::new(key.as_ref().to_vec());
        let (manifest_offset, sequence, key_directory_offset, vault_id) = read_header(&bytes)?;
        let key_slots = read_key_directory(&bytes, key_directory_offset)?;
        let mut lockbox = Self {
            bytes,
            key,
            sequence,
            manifest_offset,
            key_directory_offset,
            vault_id,
            key_slots,
            manifest: BTreeMap::new(),
            env_vars: RefCell::new(None),
            free_slots: Vec::new(),
            needs_packing: false,
        };

        if manifest_offset > 0 {
            let record = read_record(&lockbox.bytes, manifest_offset, lockbox.key.expose())?;
            if record.header.kind != RecordKind::Manifest {
                return Err(Error::CorruptHeader);
            }
            lockbox.manifest = decode_manifest(&record.payload)?;
            lockbox.rebuild_free_slots_from_manifest();
            Ok(lockbox)
        } else {
            Ok(lockbox)
        }
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn read_vault_id(bytes: &[u8]) -> Result<VaultId> {
        crate::header::read_vault_id(bytes)
    }

    pub(crate) fn write_record(&mut self, record: Vec<u8>) -> u64 {
        if let Some(index) = self
            .free_slots
            .iter()
            .position(|slot| record.len() as u64 <= slot.len)
        {
            let slot = self.free_slots.remove(index);
            let offset = slot.offset as usize;
            let end = offset + record.len();
            self.bytes[offset..end].copy_from_slice(&record);
            if slot.len > record.len() as u64 {
                self.bytes[end..(slot.offset + slot.len) as usize].fill(0);
            }
            slot.offset
        } else {
            let offset = self.bytes.len() as u64;
            self.bytes.extend_from_slice(&record);
            offset
        }
    }

    pub(crate) fn free_entry_slots(&mut self, entry: ManifestEntry) {
        if entry.chunks.is_empty() {
            self.free_slots.push(FreeSlot {
                offset: entry.record_offset,
                len: entry.record_len,
            });
            return;
        }

        for chunk in entry.chunks {
            self.free_slots.push(FreeSlot {
                offset: chunk.record_offset,
                len: chunk.record_len,
            });
        }
    }

    fn rebuild_free_slots_from_manifest(&mut self) {
        self.free_slots.clear();
        for entry in self.manifest.values() {
            if entry.deleted {
                self.free_slots.push(FreeSlot {
                    offset: entry.record_offset,
                    len: entry.record_len,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_is_not_visible_in_cleartext() {
        let mut lb = Lockbox::create("secret");
        lb.put_file("/private/tax.pdf", b"1234").unwrap();
        lb.commit().unwrap();

        let bytes = lb.to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("/private/tax.pdf"));
    }
}
