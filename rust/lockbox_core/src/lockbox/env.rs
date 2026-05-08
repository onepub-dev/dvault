use std::collections::BTreeMap;

use super::Lockbox;
use crate::format::{
    encode_env_delete_payload, encode_env_payload, encode_record, scan_env_records,
};
use crate::record::RecordKind;
use crate::security::{validate_env_name, validate_env_value};
use crate::Result;

impl Lockbox {
    pub fn set_env(&mut self, name: &str, value: &str) -> Result<()> {
        let name = validate_env_name(name)?;
        let value = validate_env_value(value)?;
        self.sequence += 1;
        let payload = encode_env_payload(&name, &value);
        let record = encode_record(RecordKind::Env, self.sequence, &payload, self.key.expose());
        self.write_record(record);
        self.ensure_env_loaded();
        self.env_vars
            .borrow_mut()
            .as_mut()
            .expect("env vars loaded")
            .insert(name, value);
        Ok(())
    }

    pub fn get_env(&self, name: &str) -> Result<Option<String>> {
        let name = validate_env_name(name)?;
        self.ensure_env_loaded();
        Ok(self
            .env_vars
            .borrow()
            .as_ref()
            .expect("env vars loaded")
            .get(&name)
            .cloned())
    }

    pub fn remove_env(&mut self, name: &str) -> Result<()> {
        let name = validate_env_name(name)?;
        self.sequence += 1;
        let payload = encode_env_delete_payload(&name);
        let record = encode_record(
            RecordKind::EnvDelete,
            self.sequence,
            &payload,
            self.key.expose(),
        );
        self.write_record(record);
        self.ensure_env_loaded();
        self.env_vars
            .borrow_mut()
            .as_mut()
            .expect("env vars loaded")
            .remove(&name);
        Ok(())
    }

    pub fn list_env(&self) -> Vec<String> {
        self.ensure_env_loaded();
        self.env_vars
            .borrow()
            .as_ref()
            .expect("env vars loaded")
            .keys()
            .cloned()
            .collect()
    }

    pub fn get_all_env(&self) -> BTreeMap<String, String> {
        self.ensure_env_loaded();
        self.env_vars
            .borrow()
            .as_ref()
            .expect("env vars loaded")
            .clone()
    }

    fn ensure_env_loaded(&self) {
        if self.env_vars.borrow().is_none() {
            let env = scan_env_records(&self.bytes, self.key.expose());
            *self.env_vars.borrow_mut() = Some(env);
        }
    }
}
