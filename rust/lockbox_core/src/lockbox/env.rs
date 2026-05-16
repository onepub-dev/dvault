use std::collections::BTreeMap;
use std::sync::Arc;

use super::Lockbox;
use crate::env_btree::{
    decode_env_node_secure, encode_env_internal, encode_env_leaf, encode_env_leaf_secure,
    env_child_groups, env_entries_from_map, env_leaf_groups, EnvChild, EnvInternal, EnvLeaf,
    EnvNode, EnvTreeNode, EnvValue,
};
use crate::free_slot::FreeSlot;
use crate::page::{page_size_for_objects, PageObject, PageObjectKind};
use crate::page_cache::SecurePageAppend;
use crate::security::{validate_env_name, validate_env_value, validate_env_value_ref};
use crate::{crypto::derive_page_content_key, secret_bytes::SecureVec};
use crate::{EnvSensitivity, Error, Result, SecretString};
use zeroize::Zeroize;

impl Lockbox {
    pub fn set_env(&mut self, name: &str, value: &str) -> Result<()> {
        let name = validate_env_name(name)?;
        let value = validate_env_value(value)?;
        self.ensure_env_loaded()?;
        let mut env = self.env_vars.borrow_mut();
        let env = env.as_mut().ok_or(Error::CorruptRecord)?;
        if matches!(env.get(&name), Some(EnvValue::Secret(_))) {
            return Err(Error::SecurityLimitExceeded(
                "environment variable is secret; delete and recreate to change sensitivity"
                    .to_string(),
            ));
        }
        env.insert(name, EnvValue::Normal(value));
        self.dirty_env = true;
        Ok(())
    }

    pub fn set_secret_env(&mut self, name: &str, value: &SecretString) -> Result<()> {
        let name = validate_env_name(name)?;
        value.with_str(validate_env_value_ref)??;
        self.ensure_env_loaded()?;
        let mut env = self.env_vars.borrow_mut();
        let env = env.as_mut().ok_or(Error::CorruptRecord)?;
        if matches!(env.get(&name), Some(EnvValue::Normal(_))) {
            return Err(Error::SecurityLimitExceeded(
                "environment variable is not secret; delete and recreate to change sensitivity"
                    .to_string(),
            ));
        }
        env.insert(name, EnvValue::Secret(Arc::new(value.try_clone()?)));
        self.dirty_env = true;
        Ok(())
    }

    pub fn get_env(&self, name: &str) -> Result<Option<String>> {
        let name = validate_env_name(name)?;
        self.ensure_env_loaded()?;
        match self
            .env_vars
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .get(name.as_str())
        {
            Some(EnvValue::Normal(value)) => Ok(Some(value.clone())),
            Some(EnvValue::Secret(_)) => Err(Error::SecurityLimitExceeded(
                "environment variable is secret; use secret access".to_string(),
            )),
            None => Ok(None),
        }
    }

    pub fn with_secret_env<R>(&self, name: &str, f: impl FnOnce(&str) -> R) -> Result<Option<R>> {
        let name = validate_env_name(name)?;
        self.ensure_env_loaded()?;
        let env = self.env_vars.borrow();
        match env.as_ref().ok_or(Error::CorruptRecord)?.get(name.as_str()) {
            Some(EnvValue::Secret(value)) => value.with_str(f).map(Some).map_err(Into::into),
            Some(EnvValue::Normal(_)) => Err(Error::SecurityLimitExceeded(
                "environment variable is not secret".to_string(),
            )),
            None => Ok(None),
        }
    }

    pub fn get_secret_env(&self, name: &str) -> Result<Option<SecretString>> {
        let name = validate_env_name(name)?;
        self.ensure_env_loaded()?;
        let env = self.env_vars.borrow();
        match env.as_ref().ok_or(Error::CorruptRecord)?.get(name.as_str()) {
            Some(EnvValue::Secret(value)) => value.try_clone().map(Some).map_err(Into::into),
            Some(EnvValue::Normal(_)) => Err(Error::SecurityLimitExceeded(
                "environment variable is not secret".to_string(),
            )),
            None => Ok(None),
        }
    }

    pub fn env_sensitivity(&self, name: &str) -> Result<Option<EnvSensitivity>> {
        let name = validate_env_name(name)?;
        self.ensure_env_loaded()?;
        Ok(self
            .env_vars
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .get(name.as_str())
            .map(EnvValue::sensitivity))
    }

    pub fn remove_env(&mut self, name: &str) -> Result<()> {
        let name = validate_env_name(name)?;
        self.ensure_env_loaded()?;
        let removed = self
            .env_vars
            .borrow_mut()
            .as_mut()
            .ok_or(Error::CorruptRecord)?
            .remove(&name)
            .is_some();
        if removed {
            self.dirty_env = true;
        }
        Ok(())
    }

    pub fn delete_env_var(&mut self, name: &str) -> Result<()> {
        self.remove_env(name)
    }

    pub fn list_env(&self) -> Result<Vec<String>> {
        self.ensure_env_loaded()?;
        Ok(self
            .env_vars
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .keys()
            .cloned()
            .collect())
    }

    pub fn list_env_with_sensitivity(&self) -> Result<Vec<(String, EnvSensitivity)>> {
        self.ensure_env_loaded()?;
        Ok(self
            .env_vars
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .iter()
            .map(|(name, value)| (name.clone(), value.sensitivity()))
            .collect())
    }

    pub fn get_all_env(&self) -> Result<BTreeMap<String, String>> {
        self.ensure_env_loaded()?;
        Ok(self
            .env_vars
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .iter()
            .filter_map(|(name, value)| {
                value
                    .as_normal()
                    .map(|value| (name.clone(), value.to_string()))
            })
            .collect())
    }

    pub(crate) fn clone_all_env_values(&self) -> Result<BTreeMap<String, EnvValue>> {
        self.ensure_env_loaded()?;
        Ok(self
            .env_vars
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .clone())
    }

    pub(crate) fn set_env_value(&mut self, name: String, value: EnvValue) -> Result<()> {
        validate_env_name(&name)?;
        value.with_plaintext(validate_env_value_ref)??;
        self.ensure_env_loaded()?;
        self.env_vars
            .borrow_mut()
            .as_mut()
            .ok_or(Error::CorruptRecord)?
            .insert(name, value);
        self.dirty_env = true;
        Ok(())
    }

    pub(crate) fn commit_env_tree(&mut self) -> Result<u64> {
        if !self.dirty_env {
            return Ok(self.env_root_offset);
        }
        self.ensure_env_loaded()?;
        let env = self
            .env_vars
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .clone();
        if env.is_empty() {
            self.env_root = None;
            self.env_leaves.clear();
            self.dirty_env = false;
            return Ok(0);
        }

        let entries = env_entries_from_map(&env);
        let mut leaves = Vec::new();
        for chunk in env_leaf_groups(&entries)? {
            let offset = self.write_env_leaf(chunk)?;
            leaves.push(EnvLeaf {
                offset,
                entries: chunk.to_vec(),
            });
        }
        let root_node = self.write_env_tree_for_leaves(&leaves)?;
        let root = root_node.offset();
        self.env_root = Some(root_node);
        self.env_leaves = leaves;
        self.dirty_env = false;
        Ok(root)
    }

    pub(crate) fn stage_env_tree_redactions(&mut self) -> Result<()> {
        if !self.dirty_env || self.env_root_offset == 0 {
            return Ok(());
        }
        let mut redactions = Vec::new();
        self.collect_env_tree_redactions(self.env_root_offset, 0, &mut redactions)?;
        for (offset, object_id) in redactions {
            self.sequence += 1;
            let object = PageObject::new(PageObjectKind::EnvLeaf, object_id, encode_env_leaf(&[])?);
            let page_size = page_size_for_objects(std::slice::from_ref(&object)) as u64;
            self.write_decoded_page_at(offset, self.sequence, vec![object])?;
            self.record_ref_counts.remove(&offset);
            self.redacted_free_slots.push(FreeSlot {
                offset,
                len: page_size,
            });
        }
        Ok(())
    }

    fn ensure_env_loaded(&self) -> Result<()> {
        if self.env_vars.borrow().is_none() {
            let env = if self.env_root_offset == 0 {
                BTreeMap::new()
            } else {
                let (env, _, _) = self.decode_env_btree(self.env_root_offset)?;
                env
            };
            *self.env_vars.borrow_mut() = Some(env);
        }
        Ok(())
    }

    fn decode_env_btree(
        &self,
        root_offset: u64,
    ) -> Result<(BTreeMap<String, EnvValue>, EnvTreeNode, Vec<EnvLeaf>)> {
        let mut env = BTreeMap::new();
        let root = self.decode_env_node_into(root_offset, &mut env, 0)?;
        let mut leaves = Vec::new();
        root.collect_leaves(&mut leaves);
        leaves.sort_by(|left, right| {
            let left_name = left
                .entries
                .first()
                .map(|entry| entry.name.as_str())
                .unwrap_or("");
            let right_name = right
                .entries
                .first()
                .map(|entry| entry.name.as_str())
                .unwrap_or("");
            left_name.cmp(right_name)
        });
        Ok((env, root, leaves))
    }

    fn decode_env_node_into(
        &self,
        offset: u64,
        env: &mut BTreeMap<String, EnvValue>,
        depth: usize,
    ) -> Result<EnvTreeNode> {
        if depth > 8 {
            return Err(Error::CorruptRecord);
        }
        match self.read_env_node(offset)? {
            EnvNode::Leaf(entries) => {
                let leaf_entries = entries.clone();
                for entry in entries {
                    env.insert(entry.name, entry.value);
                }
                Ok(EnvTreeNode::Leaf(EnvLeaf {
                    offset,
                    entries: leaf_entries,
                }))
            }
            EnvNode::Internal(children) => {
                let mut nodes = Vec::with_capacity(children.len());
                for child in children {
                    nodes.push(self.decode_env_node_into(child.offset, env, depth + 1)?);
                }
                Ok(EnvTreeNode::Internal(EnvInternal {
                    offset,
                    children: nodes,
                }))
            }
        }
    }

    fn read_env_node(&self, offset: u64) -> Result<EnvNode> {
        let env_object = self.read_env_object_secure(offset)?;
        if !matches!(
            env_object.kind,
            PageObjectKind::EnvLeaf | PageObjectKind::EnvInternal
        ) {
            return Err(Error::CorruptRecord);
        }
        let payload = env_object.secure_payload().ok_or(Error::CorruptRecord)?;
        decode_env_node_secure(payload)
    }

    fn read_env_object_secure(&self, offset: u64) -> Result<PageObject> {
        self.with_secure_page(offset, |page| {
            if page.objects.len() != 1 {
                return Err(Error::CorruptRecord);
            }
            Ok(page.objects[0].clone())
        })
    }

    fn collect_env_tree_redactions(
        &self,
        offset: u64,
        depth: usize,
        redactions: &mut Vec<(u64, u64)>,
    ) -> Result<()> {
        if depth > 8 {
            return Err(Error::CorruptRecord);
        }
        let env_object = self.read_env_object_secure(offset)?;
        if !matches!(
            env_object.kind,
            PageObjectKind::EnvLeaf | PageObjectKind::EnvInternal
        ) {
            return Err(Error::CorruptRecord);
        }
        redactions.push((offset, env_object.id));
        if env_object.kind == PageObjectKind::EnvInternal {
            let payload = env_object.secure_payload().ok_or(Error::CorruptRecord)?;
            let EnvNode::Internal(children) = decode_env_node_secure(payload)? else {
                return Err(Error::CorruptRecord);
            };
            for child in children {
                self.collect_env_tree_redactions(child.offset, depth + 1, redactions)?;
            }
        }
        Ok(())
    }

    fn write_env_tree_for_leaves(&mut self, leaves: &[EnvLeaf]) -> Result<EnvTreeNode> {
        if leaves.len() == 1 {
            return Ok(EnvTreeNode::Leaf(leaves[0].clone()));
        }
        let mut level = leaves
            .iter()
            .cloned()
            .map(EnvTreeNode::Leaf)
            .collect::<Vec<_>>();

        while level.len() > 1 {
            let mut next_level = Vec::new();
            let mut child_cursor = 0usize;
            let children = level
                .iter()
                .map(|node| EnvChild {
                    first_name: node.first_name().to_string(),
                    offset: node.offset(),
                })
                .collect::<Vec<_>>();
            for chunk in env_child_groups(&children)? {
                let offset = self.write_env_internal(chunk)?;
                let start = child_cursor;
                let end = start + chunk.len();
                child_cursor = end;
                let child_nodes = level[start..end].to_vec();
                next_level.push(EnvTreeNode::Internal(EnvInternal {
                    offset,
                    children: child_nodes,
                }));
            }
            level = next_level;
        }

        Ok(level.remove(0))
    }

    fn write_env_leaf(&mut self, entries: &[crate::env_btree::EnvEntry]) -> Result<u64> {
        let payload = encode_env_leaf_secure(entries)?;
        self.sequence += 1;
        self.append_env_page_secure(PageObjectKind::EnvLeaf, payload)
    }

    fn write_env_internal(&mut self, children: &[EnvChild]) -> Result<u64> {
        let payload = SecureVec::try_from_vec(encode_env_internal(children)?)?;
        self.sequence += 1;
        self.append_env_page_secure(PageObjectKind::EnvInternal, payload)
    }

    fn append_env_page_secure(
        &mut self,
        kind: PageObjectKind,
        mut payload: SecureVec,
    ) -> Result<u64> {
        self.flush_dirty_pages()?;
        let mut content_key = self.key.with_bytes(derive_page_content_key)?;
        let page_offset = self
            .page_manager
            .borrow_mut()
            .append_secure_single_object_page(
                &mut self.storage,
                SecurePageAppend {
                    lockbox_id: self.lockbox_id,
                    content_key: &content_key,
                    sequence: self.sequence,
                    kind,
                    object_id: self.sequence,
                    payload: &payload,
                },
            );
        content_key.zeroize();
        payload.zeroize()?;
        page_offset
    }
}
