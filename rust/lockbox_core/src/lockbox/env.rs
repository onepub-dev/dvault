use std::collections::BTreeMap;

use super::Lockbox;
use crate::format::{
    decode_env_payload, encode_env_delete_payload, encode_env_payload, scan_env_records,
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
        self.write_object_page(RecordKind::Env, self.sequence, payload)?;
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
            .get(name.as_str())
            .cloned())
    }

    pub fn remove_env(&mut self, name: &str) -> Result<()> {
        let name = validate_env_name(name)?;
        self.schedule_env_page_redactions(&name)?;
        self.sequence += 1;
        let payload = encode_env_delete_payload(&name);
        self.write_object_page(RecordKind::EnvDelete, self.sequence, payload)?;
        self.ensure_env_loaded();
        self.env_vars
            .borrow_mut()
            .as_mut()
            .expect("env vars loaded")
            .remove(&name);
        Ok(())
    }

    pub fn delete_env_var(&mut self, name: &str) -> Result<()> {
        self.remove_env(name)
    }

    fn schedule_env_page_redactions(&mut self, name: &str) -> Result<()> {
        let pages = self.inspect_pages()?;
        for page in pages {
            let decoded = self.read_page(page.offset)?;
            for object in decoded.objects {
                if object.kind == crate::page::PageObjectKind::EnvSet
                    && decode_env_payload(&object.payload)
                        .map(|(stored_name, _)| stored_name == name)
                        .unwrap_or(false)
                {
                    self.schedule_page_object_redaction(
                        page.offset,
                        crate::page::DEFAULT_PAGE_BYTES as u64,
                        object.id,
                    );
                }
            }
        }
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
            let bytes = self.bytes().expect("failed to load env records");
            let env = scan_env_records(&bytes, self.key.expose());
            *self.env_vars.borrow_mut() = Some(env);
        }
    }
}
