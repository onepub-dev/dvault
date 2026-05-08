use std::collections::BTreeMap;

use crate::payload::{decode_env_delete_payload, decode_env_payload};
use crate::record::RecordKind;
use crate::segment::scan_records;

pub(crate) fn scan_env_records(bytes: &[u8], key: &[u8]) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for record in scan_records(bytes, key).records {
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
