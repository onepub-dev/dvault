use super::Lockbox;
use crate::format::{encode_manifest, encode_record, write_header};
use crate::key_directory::write_key_directory;
use crate::record::RecordKind;
use crate::{Error, Result};
use std::fs;
use std::path::Path;

impl Lockbox {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn open_path(path: impl AsRef<Path>, key: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = fs::read(path).map_err(|err| Error::Io(err.to_string()))?;
        Self::open(bytes, key)
    }

    pub fn write_to_path(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, &self.bytes).map_err(|err| Error::Io(err.to_string()))
    }

    pub fn commit(&mut self) -> Result<()> {
        if self.needs_packing {
            self.pack_small_file_segments()?;
            self.needs_packing = false;
        }
        self.key_directory_offset = if self.key_slots.is_empty() {
            0
        } else {
            write_key_directory(&mut self.bytes, &self.key_slots)?
        };
        self.sequence += 1;
        let manifest_payload = encode_manifest(&self.manifest);
        let record = encode_record(
            RecordKind::Manifest,
            self.sequence,
            &manifest_payload,
            self.key.expose(),
        );
        let offset = self.write_record(record);
        self.manifest_offset = offset;
        write_header(
            &mut self.bytes,
            self.manifest_offset,
            self.sequence,
            self.key_directory_offset,
            self.vault_id,
        );
        Ok(())
    }
}
