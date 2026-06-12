use std::collections::BTreeMap;
use std::sync::Arc;

use super::Lockbox;
use crate::free_slot::FreeSlot;
use crate::page::{page_size_for_objects, PageObject, PageObjectKind};
use crate::page_cache::SecurePageAppend;
use crate::security::{validate_variable_value, validate_variable_value_ref};
use crate::variable_btree::{
    decode_variable_node_secure, encode_variable_internal, encode_variable_leaf,
    encode_variable_leaf_secure, variable_child_groups, variable_entries_from_map,
    variable_leaf_groups, VariableChild, VariableInternal, VariableLeaf, VariableNode,
    VariableTreeNode, VariableValue,
};
use crate::{crypto::derive_page_content_key, secret_vec::SecureVec};
use crate::{Error, Result, SecretString, VariableName, VariableSensitivity};
use zeroize::Zeroize;

/// Borrowed variable value yielded by `Lockbox::visit_variables`.
#[derive(Debug)]
pub enum VariableValueRef<'a> {
    /// Plain variable value.
    Normal(&'a str),
    /// Secret variable value; use `SecretString::with_str` for scoped plaintext access.
    Secret(&'a SecretString),
}

impl Lockbox {
    /// Store or replace a non-secret variable.
    ///
    /// Returns `Error::InvalidInput` if the value contains unsupported
    /// characters, `Error::SecurityLimitExceeded` if the value exceeds the
    /// configured variable value size limit, `Error::InvalidOperation` when
    /// attempting to overwrite an existing secret variable as non-secret, and
    /// `Error::CorruptRecord` if stored variable metadata cannot be loaded.
    pub fn set_variable(&mut self, name: &VariableName, value: &str) -> Result<()> {
        let value = validate_variable_value(value)?;
        self.ensure_variables_loaded()?;
        let mut variables = self.variables.borrow_mut();
        let variables = variables.as_mut().ok_or(Error::CorruptRecord)?;
        if matches!(variables.get(name), Some(VariableValue::Secret(_))) {
            return Err(Error::InvalidOperation(
                "variable is secret; delete and recreate to change sensitivity".to_string(),
            ));
        }
        variables.insert(name.clone(), VariableValue::Normal(value));
        self.dirty_variables = true;
        Ok(())
    }

    /// Store or replace a secret variable.
    ///
    /// Secret values remain in secure storage. Changing an existing variable
    /// between normal and secret sensitivity requires deleting it first.
    ///
    /// Returns `Error::InvalidInput` if the secret plaintext contains
    /// unsupported characters, `Error::SecurityLimitExceeded` if the secret
    /// plaintext exceeds the configured variable value size limit,
    /// `Error::InvalidOperation` when attempting to overwrite an existing
    /// non-secret variable as secret, and `Error::CorruptRecord` if stored
    /// variable metadata cannot be loaded.
    pub fn set_secret_variable(&mut self, name: &VariableName, value: &SecretString) -> Result<()> {
        value.with_str(validate_variable_value_ref)??;
        self.ensure_variables_loaded()?;
        let mut variables = self.variables.borrow_mut();
        let variables = variables.as_mut().ok_or(Error::CorruptRecord)?;
        if matches!(variables.get(name), Some(VariableValue::Normal(_))) {
            return Err(Error::InvalidOperation(
                "variable is not secret; delete and recreate to change sensitivity".to_string(),
            ));
        }
        variables.insert(
            name.clone(),
            VariableValue::Secret(Arc::new(value.try_clone()?)),
        );
        self.dirty_variables = true;
        Ok(())
    }

    /// Return a non-secret variable by name.
    ///
    /// Returns `Ok(None)` when the variable is absent. Returns
    /// `Error::InvalidOperation` if the variable exists but is secret, and
    /// `Error::CorruptRecord` if stored variable metadata cannot be loaded.
    pub fn get_variable(&self, name: &VariableName) -> Result<Option<String>> {
        self.ensure_variables_loaded()?;
        match self
            .variables
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .get(name)
        {
            Some(VariableValue::Normal(value)) => Ok(Some(value.clone())),
            Some(VariableValue::Secret(_)) => Err(Error::InvalidOperation(
                "variable is secret; use secret access".to_string(),
            )),
            None => Ok(None),
        }
    }

    /// Access a secret variable within a callback.
    ///
    /// The callback receives the `SecretString` handle. Use
    /// `SecretString::with_str` inside the callback when plaintext access is
    /// required.
    ///
    /// Returns `Ok(None)` when the variable is absent. Returns
    /// `Error::InvalidOperation` if the variable exists but is non-secret,
    /// and `Error::CorruptRecord` if stored variable metadata cannot be
    /// loaded.
    pub fn with_secret_variable<R>(
        &self,
        name: &VariableName,
        f: impl FnOnce(&SecretString) -> R,
    ) -> Result<Option<R>> {
        self.ensure_variables_loaded()?;
        let variables = self.variables.borrow();
        match variables.as_ref().ok_or(Error::CorruptRecord)?.get(name) {
            Some(VariableValue::Secret(value)) => Ok(Some(f(value))),
            Some(VariableValue::Normal(_)) => Err(Error::InvalidOperation(
                "variable is not secret".to_string(),
            )),
            None => Ok(None),
        }
    }

    /// Return the sensitivity of a variable, if it exists.
    ///
    /// Returns `Error::CorruptRecord` if stored variable metadata cannot be
    /// loaded.
    pub fn variable_sensitivity(&self, name: &VariableName) -> Result<Option<VariableSensitivity>> {
        self.ensure_variables_loaded()?;
        Ok(self
            .variables
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .get(name)
            .map(VariableValue::sensitivity))
    }

    /// Delete a variable if it exists.
    ///
    /// Returns `Error::CorruptRecord` if stored variable metadata cannot be
    /// loaded.
    pub fn delete_variable(&mut self, name: &VariableName) -> Result<()> {
        self.ensure_variables_loaded()?;
        let removed = self
            .variables
            .borrow_mut()
            .as_mut()
            .ok_or(Error::CorruptRecord)?
            .remove(name)
            .is_some();
        if removed {
            self.dirty_variables = true;
        }
        Ok(())
    }

    /// List variable names with their sensitivity.
    ///
    /// Returns `Error::CorruptRecord` if stored variable metadata cannot be
    /// loaded.
    pub fn list_variables(&self) -> Result<Vec<(VariableName, VariableSensitivity)>> {
        self.ensure_variables_loaded()?;
        Ok(self
            .variables
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .iter()
            .map(|(name, value)| (name.clone(), value.sensitivity()))
            .collect())
    }

    /// Visit every variable.
    ///
    /// Normal values are provided as borrowed strings. Secret values are
    /// provided as `SecretString` references so callers must explicitly use the
    /// secret type's scoped accessors.
    ///
    /// Returns `Error::CorruptRecord` if stored variable metadata cannot be
    /// loaded, or any error returned by the visitor callback.
    pub fn visit_variables(
        &self,
        mut f: impl FnMut(&VariableName, VariableValueRef<'_>) -> Result<()>,
    ) -> Result<()> {
        self.ensure_variables_loaded()?;
        for (name, value) in self
            .variables
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
        {
            match value {
                VariableValue::Normal(value) => {
                    f(name, VariableValueRef::Normal(value))?;
                }
                VariableValue::Secret(value) => {
                    f(name, VariableValueRef::Secret(value))?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn clone_all_variable_values(
        &self,
    ) -> Result<BTreeMap<VariableName, VariableValue>> {
        self.ensure_variables_loaded()?;
        Ok(self
            .variables
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .clone())
    }

    pub(crate) fn set_variable_value(
        &mut self,
        name: VariableName,
        value: VariableValue,
    ) -> Result<()> {
        value.with_plaintext(validate_variable_value_ref)??;
        self.ensure_variables_loaded()?;
        self.variables
            .borrow_mut()
            .as_mut()
            .ok_or(Error::CorruptRecord)?
            .insert(name, value);
        self.dirty_variables = true;
        Ok(())
    }

    pub(crate) fn commit_variable_tree(&mut self) -> Result<u64> {
        if !self.dirty_variables {
            return Ok(self.variable_root_offset);
        }
        self.ensure_variables_loaded()?;
        let variables = self
            .variables
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .clone();
        if variables.is_empty() {
            self.variable_root = None;
            self.variable_leaves.clear();
            self.dirty_variables = false;
            return Ok(0);
        }

        let entries = variable_entries_from_map(&variables);
        let mut leaves = Vec::new();
        for chunk in variable_leaf_groups(&entries)? {
            let offset = self.write_variable_leaf(chunk)?;
            leaves.push(VariableLeaf {
                offset,
                entries: chunk.to_vec(),
            });
        }
        let root_node = self.write_variable_tree_for_leaves(&leaves)?;
        let root = root_node.offset();
        self.variable_root = Some(root_node);
        self.variable_leaves = leaves;
        self.dirty_variables = false;
        Ok(root)
    }

    pub(crate) fn stage_variable_tree_redactions(&mut self) -> Result<()> {
        if !self.dirty_variables || self.variable_root_offset == 0 {
            return Ok(());
        }
        let mut redactions = Vec::new();
        self.collect_variable_tree_redactions(self.variable_root_offset, 0, &mut redactions)?;
        for (offset, object_id) in redactions {
            self.sequence += 1;
            let object = PageObject::new(
                PageObjectKind::VariableLeaf,
                object_id,
                encode_variable_leaf(&[])?,
            );
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

    fn ensure_variables_loaded(&self) -> Result<()> {
        if self.variables.borrow().is_none() {
            let variables = if self.variable_root_offset == 0 {
                BTreeMap::new()
            } else {
                let (variables, _, _) = self.decode_variable_btree(self.variable_root_offset)?;
                variables
            };
            *self.variables.borrow_mut() = Some(variables);
        }
        Ok(())
    }

    fn decode_variable_btree(
        &self,
        root_offset: u64,
    ) -> Result<(
        BTreeMap<VariableName, VariableValue>,
        VariableTreeNode,
        Vec<VariableLeaf>,
    )> {
        let mut variables = BTreeMap::new();
        let root = self.decode_variable_node_into(root_offset, &mut variables, 0)?;
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
        Ok((variables, root, leaves))
    }

    fn decode_variable_node_into(
        &self,
        offset: u64,
        variables: &mut BTreeMap<VariableName, VariableValue>,
        depth: usize,
    ) -> Result<VariableTreeNode> {
        if depth > 8 {
            return Err(Error::CorruptRecord);
        }
        match self.read_variable_node(offset)? {
            VariableNode::Leaf(entries) => {
                let leaf_entries = entries.clone();
                for entry in entries {
                    variables.insert(VariableName::new(entry.name)?, entry.value);
                }
                Ok(VariableTreeNode::Leaf(VariableLeaf {
                    offset,
                    entries: leaf_entries,
                }))
            }
            VariableNode::Internal(children) => {
                let mut nodes = Vec::with_capacity(children.len());
                for child in children {
                    nodes.push(self.decode_variable_node_into(
                        child.offset,
                        variables,
                        depth + 1,
                    )?);
                }
                Ok(VariableTreeNode::Internal(VariableInternal {
                    offset,
                    children: nodes,
                }))
            }
        }
    }

    fn read_variable_node(&self, offset: u64) -> Result<VariableNode> {
        let variable_object = self.read_variable_object_secure(offset)?;
        if !matches!(
            variable_object.kind,
            PageObjectKind::VariableLeaf | PageObjectKind::VariableInternal
        ) {
            return Err(Error::CorruptRecord);
        }
        let payload = variable_object
            .secure_payload()
            .ok_or(Error::CorruptRecord)?;
        decode_variable_node_secure(payload)
    }

    fn read_variable_object_secure(&self, offset: u64) -> Result<PageObject> {
        self.with_secure_page(offset, |page| {
            if page.objects.len() != 1 {
                return Err(Error::CorruptRecord);
            }
            Ok(page.objects[0].clone())
        })
    }

    fn collect_variable_tree_redactions(
        &self,
        offset: u64,
        depth: usize,
        redactions: &mut Vec<(u64, u64)>,
    ) -> Result<()> {
        if depth > 8 {
            return Err(Error::CorruptRecord);
        }
        let variable_object = self.read_variable_object_secure(offset)?;
        if !matches!(
            variable_object.kind,
            PageObjectKind::VariableLeaf | PageObjectKind::VariableInternal
        ) {
            return Err(Error::CorruptRecord);
        }
        redactions.push((offset, variable_object.id));
        if variable_object.kind == PageObjectKind::VariableInternal {
            let payload = variable_object
                .secure_payload()
                .ok_or(Error::CorruptRecord)?;
            let VariableNode::Internal(children) = decode_variable_node_secure(payload)? else {
                return Err(Error::CorruptRecord);
            };
            for child in children {
                self.collect_variable_tree_redactions(child.offset, depth + 1, redactions)?;
            }
        }
        Ok(())
    }

    fn write_variable_tree_for_leaves(
        &mut self,
        leaves: &[VariableLeaf],
    ) -> Result<VariableTreeNode> {
        if leaves.len() == 1 {
            return Ok(VariableTreeNode::Leaf(leaves[0].clone()));
        }
        let mut level = leaves
            .iter()
            .cloned()
            .map(VariableTreeNode::Leaf)
            .collect::<Vec<_>>();

        while level.len() > 1 {
            let mut next_level = Vec::new();
            let mut child_cursor = 0usize;
            let children = level
                .iter()
                .map(|node| VariableChild {
                    first_name: node.first_name().to_string(),
                    offset: node.offset(),
                })
                .collect::<Vec<_>>();
            for chunk in variable_child_groups(&children)? {
                let offset = self.write_variable_internal(chunk)?;
                let start = child_cursor;
                let end = start + chunk.len();
                child_cursor = end;
                let child_nodes = level[start..end].to_vec();
                next_level.push(VariableTreeNode::Internal(VariableInternal {
                    offset,
                    children: child_nodes,
                }));
            }
            level = next_level;
        }

        Ok(level.remove(0))
    }

    fn write_variable_leaf(
        &mut self,
        entries: &[crate::variable_btree::VariableEntry],
    ) -> Result<u64> {
        let payload = encode_variable_leaf_secure(entries)?;
        self.sequence += 1;
        self.append_variable_page_secure(PageObjectKind::VariableLeaf, payload)
    }

    fn write_variable_internal(&mut self, children: &[VariableChild]) -> Result<u64> {
        let payload = SecureVec::try_from_vec(encode_variable_internal(children)?)?;
        self.sequence += 1;
        self.append_variable_page_secure(PageObjectKind::VariableInternal, payload)
    }

    fn append_variable_page_secure(
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
