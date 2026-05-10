use std::collections::BTreeMap;

use crate::lockbox_id::LockboxId;
use crate::page::scan_page_records;
use crate::payload::{decode_env_delete_payload, decode_env_payload};
use crate::record::RecordKind;

pub(crate) fn scan_env_records(bytes: &[u8], key: &[u8]) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    let lockbox_id = bytes
        .get(40..56)
        .and_then(|bytes| bytes.try_into().ok())
        .map(LockboxId::from_bytes)
        .unwrap_or_else(|| LockboxId::from_bytes([0; 16]));
    for record in scan_page_records(bytes, lockbox_id, key).records {
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
