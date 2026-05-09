use std::collections::BTreeMap;

use crate::payload::{decode_env_delete_payload, decode_env_payload};
use crate::record::RecordKind;
use crate::segment_page::scan_segment_page_records;
use crate::vault_id::VaultId;

pub(crate) fn scan_env_records(bytes: &[u8], key: &[u8]) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    let vault_id = bytes
        .get(40..56)
        .and_then(|bytes| bytes.try_into().ok())
        .map(VaultId::from_bytes)
        .unwrap_or_else(|| VaultId::from_bytes([0; 16]));
    for record in scan_segment_page_records(bytes, vault_id, key).records {
        match record.header.kind {
            RecordKind::Env => {
                if let Ok((name, value)) = decode_env_payload(&record.payload) {
                    env.insert(name, value);
                }
            }
            RecordKind::EnvDelete => {
                if let Ok(name) = decode_env_delete_payload(&record.payload) {
                    env.remove(&name);
                }
            }
            _ => {}
        }
    }
    env
}
