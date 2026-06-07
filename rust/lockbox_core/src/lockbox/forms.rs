use std::collections::{BTreeMap, BTreeSet};

use super::Lockbox;
use crate::form::{
    validate_form_alias, validate_form_field_id, validate_form_label, validate_form_record_name,
    validate_form_value, FormDefinition, FormFieldDefinition, FormFieldValue, FormRecord,
    FormTypeId, FormValue,
};
use crate::form_btree::{
    decode_form_node_secure, definition_key, encode_form_internal, encode_form_leaf_secure,
    form_child_groups, form_entries_from_maps, form_leaf_groups, record_key, FormChild, FormEntry,
    FormEntryValue, FormInternal, FormLeaf, FormNode, FormTreeNode,
};
use crate::free_slot::FreeSlot;
use crate::page::{page_size_for_objects, PageObject, PageObjectKind};
use crate::page_cache::SecurePageAppend;
use crate::secret_vec::SecureVec;
use crate::{crypto::derive_page_content_key, Error, LockboxPath, Result, SecretString};
use zeroize::Zeroize;

impl Lockbox {
    pub fn define_form(
        &mut self,
        alias: &str,
        name: &str,
        fields: Vec<FormFieldDefinition>,
    ) -> Result<FormDefinition> {
        let alias = validate_form_alias(alias)?;
        match self.resolve_form_definition(&alias) {
            Ok(existing) => self.revise_form_definition(&existing.type_id, name, fields),
            Err(Error::NotFound(_)) => {
                let type_id = FormTypeId::new_random()?;
                self.define_form_with_type_id(type_id, &alias, name, fields)
            }
            Err(err) => Err(err),
        }
    }

    pub fn define_form_with_type_id(
        &mut self,
        type_id: FormTypeId,
        alias: &str,
        name: &str,
        fields: Vec<FormFieldDefinition>,
    ) -> Result<FormDefinition> {
        let alias = validate_form_alias(alias)?;
        if self.latest_form_definition_by_type(&type_id)?.is_some() {
            return self.revise_form_definition(&type_id, name, fields);
        }
        let definition = validated_definition(type_id, alias, 1, name, fields)?;
        self.ensure_forms_loaded()?;
        self.form_definitions
            .borrow_mut()
            .as_mut()
            .ok_or(Error::CorruptRecord)?
            .insert(
                definition_key(&definition.type_id, definition.revision),
                definition.clone(),
            );
        self.dirty_form_keys
            .insert(definition_key(&definition.type_id, definition.revision));
        self.dirty_forms = true;
        Ok(definition)
    }

    pub fn revise_form_definition(
        &mut self,
        type_id: &FormTypeId,
        name: &str,
        fields: Vec<FormFieldDefinition>,
    ) -> Result<FormDefinition> {
        let previous = self
            .latest_form_definition_by_type(type_id)?
            .ok_or_else(|| Error::NotFound(format!("form type {type_id}")))?;
        let definition = validated_definition(
            type_id.clone(),
            previous.alias.clone(),
            previous.revision + 1,
            name,
            fields,
        )?;
        self.form_definitions
            .borrow_mut()
            .as_mut()
            .ok_or(Error::CorruptRecord)?
            .insert(
                definition_key(&definition.type_id, definition.revision),
                definition.clone(),
            );
        self.dirty_form_keys
            .insert(definition_key(&definition.type_id, definition.revision));
        self.dirty_forms = true;
        Ok(definition)
    }

    pub fn resolve_form_definition(&self, reference: &str) -> Result<FormDefinition> {
        self.ensure_forms_loaded()?;
        if let Ok(type_id) = FormTypeId::new(reference) {
            return self
                .latest_form_definition_by_type(&type_id)?
                .ok_or_else(|| Error::NotFound(format!("form type {type_id}")));
        }
        let alias = validate_form_alias(reference)?;
        let matches = self
            .latest_form_definitions()?
            .into_iter()
            .filter(|definition| definition.alias == alias)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [definition] => Ok(definition.clone()),
            [] => Err(Error::NotFound(format!("form alias {alias}"))),
            _ => Err(Error::InvalidOperation(format!(
                "form alias {alias} is ambiguous; use a form type id"
            ))),
        }
    }

    pub fn list_form_definitions(&self) -> Result<Vec<FormDefinition>> {
        self.latest_form_definitions()
    }

    pub fn list_form_definition_revisions(
        &self,
        type_id: &FormTypeId,
    ) -> Result<Vec<FormDefinition>> {
        self.ensure_forms_loaded()?;
        let mut definitions = self
            .form_definitions
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .values()
            .filter(|definition| definition.type_id == *type_id)
            .cloned()
            .collect::<Vec<_>>();
        definitions.sort_by_key(|definition| definition.revision);
        Ok(definitions)
    }

    pub fn create_form_record(
        &mut self,
        path: &LockboxPath,
        type_reference: &str,
        name: &str,
    ) -> Result<FormRecord> {
        let path = path.file_path()?;
        let name = validate_form_record_name(name)?;
        self.ensure_forms_loaded()?;
        if self
            .form_records
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .contains_key(&path)
        {
            return Err(Error::AlreadyExists(path.to_string()));
        }
        let definition = self.resolve_form_definition(type_reference)?;
        let record = FormRecord {
            path: path.clone(),
            name,
            type_id: definition.type_id,
            definition_alias: definition.alias,
            definition_revision: definition.revision,
            values: Vec::new(),
        };
        self.form_records
            .borrow_mut()
            .as_mut()
            .ok_or(Error::CorruptRecord)?
            .insert(path, record.clone());
        self.dirty_form_keys.insert(record_key(&record.path));
        self.dirty_forms = true;
        Ok(record)
    }

    pub fn get_form_record(&self, path: &LockboxPath) -> Result<Option<FormRecord>> {
        self.ensure_forms_loaded()?;
        Ok(self
            .form_records
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .get(path)
            .cloned())
    }

    pub fn list_form_records(&self) -> Result<Vec<FormRecord>> {
        self.ensure_forms_loaded()?;
        Ok(self
            .form_records
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .values()
            .cloned()
            .collect())
    }

    pub fn delete_form_record(&mut self, path: &LockboxPath) -> Result<()> {
        let path = path.file_path()?;
        self.ensure_forms_loaded()?;
        let mut records = self.form_records.borrow_mut();
        let records = records.as_mut().ok_or(Error::CorruptRecord)?;
        if records.remove(&path).is_none() {
            return Err(Error::NotFound(format!("form record {path}")));
        }
        self.dirty_form_keys.insert(record_key(&path));
        self.dirty_forms = true;
        Ok(())
    }

    pub fn set_form_field_normal(
        &mut self,
        path: &LockboxPath,
        field_id: &str,
        value: &str,
    ) -> Result<()> {
        self.set_form_field(path, field_id, FormValue::Normal(value.to_string()))
    }

    pub fn set_form_field_secret(
        &mut self,
        path: &LockboxPath,
        field_id: &str,
        value: &SecretString,
    ) -> Result<()> {
        self.set_form_field(
            path,
            field_id,
            FormValue::Secret(std::sync::Arc::new(value.try_clone()?)),
        )
    }

    pub fn set_form_field(
        &mut self,
        path: &LockboxPath,
        field_id: &str,
        value: FormValue,
    ) -> Result<()> {
        let field_id = validate_form_field_id(field_id)?;
        self.ensure_forms_loaded()?;
        let type_id = self
            .form_records
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .get(path)
            .ok_or_else(|| Error::NotFound(format!("form record {path}")))?
            .type_id
            .clone();
        let definition = self
            .latest_form_definition_by_type(&type_id)?
            .ok_or_else(|| Error::NotFound(format!("form type {type_id}")))?;
        let field = definition
            .fields
            .iter()
            .find(|field| field.id == field_id)
            .ok_or_else(|| Error::InvalidInput(format!("unknown form field: {field_id}")))?;
        validate_form_value(field.kind, &value)?;
        let value_record = FormFieldValue {
            field_id,
            captured_label: field.label.clone(),
            kind: field.kind,
            value,
        };
        let mut records = self.form_records.borrow_mut();
        let records = records.as_mut().ok_or(Error::CorruptRecord)?;
        let record = records
            .get_mut(path)
            .ok_or_else(|| Error::NotFound(format!("form record {path}")))?;
        match record
            .values
            .iter_mut()
            .find(|existing| existing.field_id == value_record.field_id)
        {
            Some(existing) => *existing = value_record,
            None => record.values.push(value_record),
        }
        record.definition_revision = definition.revision;
        record.definition_alias = definition.alias;
        self.dirty_form_keys.insert(record_key(path));
        self.dirty_forms = true;
        Ok(())
    }

    pub fn get_form_field(
        &self,
        path: &LockboxPath,
        field_id: &str,
    ) -> Result<Option<FormFieldValue>> {
        let field_id = validate_form_field_id(field_id)?;
        self.ensure_forms_loaded()?;
        Ok(self
            .form_records
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .get(path)
            .and_then(|record| {
                record
                    .values
                    .iter()
                    .find(|value| value.field_id == field_id)
                    .cloned()
            }))
    }

    pub(crate) fn clone_all_form_state(
        &self,
    ) -> Result<(
        BTreeMap<String, FormDefinition>,
        BTreeMap<LockboxPath, FormRecord>,
    )> {
        self.ensure_forms_loaded()?;
        Ok((
            self.form_definitions
                .borrow()
                .as_ref()
                .ok_or(Error::CorruptRecord)?
                .clone(),
            self.form_records
                .borrow()
                .as_ref()
                .ok_or(Error::CorruptRecord)?
                .clone(),
        ))
    }

    pub(crate) fn set_form_definition_value(
        &mut self,
        key: String,
        definition: FormDefinition,
    ) -> Result<()> {
        self.ensure_forms_loaded()?;
        let dirty_key = key.clone();
        self.form_definitions
            .borrow_mut()
            .as_mut()
            .ok_or(Error::CorruptRecord)?
            .insert(key, definition);
        self.dirty_form_keys.insert(dirty_key);
        self.dirty_forms = true;
        Ok(())
    }

    pub(crate) fn set_form_record_value(
        &mut self,
        path: LockboxPath,
        record: FormRecord,
    ) -> Result<()> {
        self.ensure_forms_loaded()?;
        let dirty_key = record_key(&path);
        self.form_records
            .borrow_mut()
            .as_mut()
            .ok_or(Error::CorruptRecord)?
            .insert(path, record);
        self.dirty_form_keys.insert(dirty_key);
        self.dirty_forms = true;
        Ok(())
    }

    pub(crate) fn commit_form_tree(&mut self) -> Result<u64> {
        if !self.dirty_forms {
            return Ok(self.form_root_offset);
        }
        self.ensure_forms_loaded()?;
        let definitions = self
            .form_definitions
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .clone();
        let records = self
            .form_records
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .clone();
        if definitions.is_empty() && records.is_empty() {
            self.form_root = None;
            self.form_leaves.clear();
            self.dirty_form_keys.clear();
            self.dirty_forms = false;
            return Ok(0);
        }
        let root = if self.form_leaves.is_empty() {
            self.rebuild_form_btree(definitions, records)?
        } else {
            self.write_incremental_form_btree(definitions, records)?
        };
        self.dirty_form_keys.clear();
        self.dirty_forms = false;
        Ok(root)
    }

    pub(crate) fn stage_form_tree_redactions(&mut self) -> Result<()> {
        if !self.dirty_forms || self.form_root_offset == 0 {
            return Ok(());
        }
        let mut redactions = Vec::new();
        if !self.dirty_form_keys.is_empty() {
            let Some(root) = self.form_root.clone() else {
                self.collect_form_tree_redactions(self.form_root_offset, 0, &mut redactions)?;
                return self.write_form_redactions(redactions);
            };
            collect_dirty_form_tree_redactions_from_node(
                &root,
                &self.dirty_form_keys,
                &mut redactions,
            );
        } else {
            self.collect_form_tree_redactions(self.form_root_offset, 0, &mut redactions)?;
        }
        self.write_form_redactions(redactions)
    }

    fn write_form_redactions(&mut self, redactions: Vec<(u64, u64)>) -> Result<()> {
        for (offset, object_id) in redactions {
            self.sequence += 1;
            let payload = encode_form_leaf_secure(&[])?;
            let object = PageObject::new_secure(PageObjectKind::FormLeaf, object_id, payload);
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

    fn rebuild_form_btree(
        &mut self,
        definitions: BTreeMap<String, FormDefinition>,
        records: BTreeMap<LockboxPath, FormRecord>,
    ) -> Result<u64> {
        let entries = form_entries_from_maps(&definitions, &records);
        let mut leaves = Vec::new();
        for chunk in form_leaf_groups(&entries)? {
            let (offset, object_id) = self.write_form_leaf(chunk)?;
            leaves.push(FormLeaf {
                offset,
                object_id,
                entries: chunk.to_vec(),
            });
        }
        let root_node = self.write_form_tree_for_leaves(&leaves)?;
        let root = root_node.offset();
        self.form_root = Some(root_node);
        self.form_leaves = leaves;
        Ok(root)
    }

    fn write_incremental_form_btree(
        &mut self,
        definitions: BTreeMap<String, FormDefinition>,
        records: BTreeMap<LockboxPath, FormRecord>,
    ) -> Result<u64> {
        let dirty = self.dirty_form_keys.clone();
        let all_entries = form_entries_from_maps(&definitions, &records);
        let mut rebuilt_leaves = Vec::new();
        let mut cursor = 0usize;
        let old_leaves = std::mem::take(&mut self.form_leaves);
        for (index, leaf) in old_leaves.iter().enumerate() {
            let Some(first) = leaf.entries.first().map(|entry| entry.key.as_str()) else {
                continue;
            };
            let next = old_leaves
                .get(index + 1)
                .and_then(|leaf| leaf.entries.first())
                .map(|entry| entry.key.as_str());
            while cursor < all_entries.len() && all_entries[cursor].key.as_str() < first {
                let chunk_start = cursor;
                cursor += 1;
                while cursor < all_entries.len()
                    && next.is_none_or(|next| all_entries[cursor].key.as_str() < next)
                    && dirty
                        .iter()
                        .all(|key| key.as_str() != all_entries[cursor].key.as_str())
                {
                    cursor += 1;
                }
                for chunk in form_leaf_groups(&all_entries[chunk_start..cursor])? {
                    let (offset, object_id) = self.write_form_leaf(chunk)?;
                    rebuilt_leaves.push(FormLeaf {
                        offset,
                        object_id,
                        entries: chunk.to_vec(),
                    });
                }
            }

            let start = cursor;
            while cursor < all_entries.len()
                && next.is_none_or(|next| all_entries[cursor].key.as_str() < next)
            {
                cursor += 1;
            }
            let replacement_entries = &all_entries[start..cursor];
            let overlaps_dirty = replacement_entries
                .iter()
                .any(|entry| dirty.contains(&entry.key))
                || dirty.iter().any(|key| {
                    key.as_str() >= first && next.is_none_or(|next| key.as_str() < next)
                });
            if !overlaps_dirty {
                rebuilt_leaves.push(leaf.clone());
                continue;
            }
            for chunk in form_leaf_groups(replacement_entries)? {
                let (offset, object_id) = self.write_form_leaf(chunk)?;
                rebuilt_leaves.push(FormLeaf {
                    offset,
                    object_id,
                    entries: chunk.to_vec(),
                });
            }
        }

        if cursor < all_entries.len() {
            for chunk in form_leaf_groups(&all_entries[cursor..])? {
                let (offset, object_id) = self.write_form_leaf(chunk)?;
                rebuilt_leaves.push(FormLeaf {
                    offset,
                    object_id,
                    entries: chunk.to_vec(),
                });
            }
        }
        rebuilt_leaves.sort_by(|left, right| leaf_first_key(left).cmp(leaf_first_key(right)));
        let root_node = if form_leaf_directory_is_compatible(&old_leaves, &rebuilt_leaves) {
            let old_root = self.form_root.take().ok_or(Error::CorruptRecord)?;
            self.rewrite_compatible_form_tree(old_root, &rebuilt_leaves)?
        } else {
            self.write_form_tree_for_leaves(&rebuilt_leaves)?
        };
        let root = root_node.offset();
        self.form_root = Some(root_node);
        self.form_leaves = rebuilt_leaves;
        Ok(root)
    }

    fn latest_form_definitions(&self) -> Result<Vec<FormDefinition>> {
        self.ensure_forms_loaded()?;
        let mut latest = BTreeMap::<FormTypeId, FormDefinition>::new();
        for definition in self
            .form_definitions
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .values()
        {
            let replace = latest
                .get(&definition.type_id)
                .is_none_or(|existing| definition.revision > existing.revision);
            if replace {
                latest.insert(definition.type_id.clone(), definition.clone());
            }
        }
        Ok(latest.into_values().collect())
    }

    fn latest_form_definition_by_type(
        &self,
        type_id: &FormTypeId,
    ) -> Result<Option<FormDefinition>> {
        self.ensure_forms_loaded()?;
        Ok(self
            .form_definitions
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .values()
            .filter(|definition| &definition.type_id == type_id)
            .max_by_key(|definition| definition.revision)
            .cloned())
    }

    fn ensure_forms_loaded(&self) -> Result<()> {
        if self.form_definitions.borrow().is_none() || self.form_records.borrow().is_none() {
            let (definitions, records) = if self.form_root_offset == 0 {
                (BTreeMap::new(), BTreeMap::new())
            } else {
                let (definitions, records, _, _) = self.decode_form_btree(self.form_root_offset)?;
                (definitions, records)
            };
            *self.form_definitions.borrow_mut() = Some(definitions);
            *self.form_records.borrow_mut() = Some(records);
        }
        Ok(())
    }

    fn decode_form_btree(
        &self,
        root_offset: u64,
    ) -> Result<(
        BTreeMap<String, FormDefinition>,
        BTreeMap<LockboxPath, FormRecord>,
        FormTreeNode,
        Vec<FormLeaf>,
    )> {
        let mut definitions = BTreeMap::new();
        let mut records = BTreeMap::new();
        let root = self.decode_form_node_into(root_offset, &mut definitions, &mut records, 0)?;
        let mut leaves = Vec::new();
        root.collect_leaves(&mut leaves);
        leaves.sort_by(|left, right| {
            let left_key = left
                .entries
                .first()
                .map(|entry| entry.key.as_str())
                .unwrap_or("");
            let right_key = right
                .entries
                .first()
                .map(|entry| entry.key.as_str())
                .unwrap_or("");
            left_key.cmp(right_key)
        });
        Ok((definitions, records, root, leaves))
    }

    fn decode_form_node_into(
        &self,
        offset: u64,
        definitions: &mut BTreeMap<String, FormDefinition>,
        records: &mut BTreeMap<LockboxPath, FormRecord>,
        depth: usize,
    ) -> Result<FormTreeNode> {
        if depth > 8 {
            return Err(Error::CorruptRecord);
        }
        let (node, object_id) = self.read_form_node(offset)?;
        match node {
            FormNode::Leaf(entries) => {
                let leaf_entries = entries.clone();
                for entry in entries {
                    match entry.value {
                        FormEntryValue::Definition(definition) => {
                            definitions.insert(entry.key, definition);
                        }
                        FormEntryValue::Record(record) => {
                            records.insert(record.path.clone(), record);
                        }
                    }
                }
                Ok(FormTreeNode::Leaf(FormLeaf {
                    offset,
                    object_id,
                    entries: leaf_entries,
                }))
            }
            FormNode::Internal(children) => {
                let mut nodes = Vec::with_capacity(children.len());
                for child in children {
                    nodes.push(self.decode_form_node_into(
                        child.offset,
                        definitions,
                        records,
                        depth + 1,
                    )?);
                }
                Ok(FormTreeNode::Internal(FormInternal {
                    offset,
                    object_id,
                    children: nodes,
                }))
            }
        }
    }

    fn read_form_node(&self, offset: u64) -> Result<(FormNode, u64)> {
        let form_object = self.read_form_object_secure(offset)?;
        if !matches!(
            form_object.kind,
            PageObjectKind::FormLeaf | PageObjectKind::FormInternal
        ) {
            return Err(Error::CorruptRecord);
        }
        let payload = form_object.secure_payload().ok_or(Error::CorruptRecord)?;
        Ok((decode_form_node_secure(payload)?, form_object.id))
    }

    fn read_form_object_secure(&self, offset: u64) -> Result<PageObject> {
        self.with_secure_page(offset, |page| {
            if page.objects.len() != 1 {
                return Err(Error::CorruptRecord);
            }
            Ok(page.objects[0].clone())
        })
    }

    fn collect_form_tree_redactions(
        &self,
        offset: u64,
        depth: usize,
        redactions: &mut Vec<(u64, u64)>,
    ) -> Result<()> {
        if depth > 8 {
            return Err(Error::CorruptRecord);
        }
        let form_object = self.read_form_object_secure(offset)?;
        if !matches!(
            form_object.kind,
            PageObjectKind::FormLeaf | PageObjectKind::FormInternal
        ) {
            return Err(Error::CorruptRecord);
        }
        redactions.push((offset, form_object.id));
        if form_object.kind == PageObjectKind::FormInternal {
            let payload = form_object.secure_payload().ok_or(Error::CorruptRecord)?;
            let FormNode::Internal(children) = decode_form_node_secure(payload)? else {
                return Err(Error::CorruptRecord);
            };
            for child in children {
                self.collect_form_tree_redactions(child.offset, depth + 1, redactions)?;
            }
        }
        Ok(())
    }

    fn write_form_tree_for_leaves(&mut self, leaves: &[FormLeaf]) -> Result<FormTreeNode> {
        if leaves.len() == 1 {
            return Ok(FormTreeNode::Leaf(leaves[0].clone()));
        }
        let mut level = leaves
            .iter()
            .cloned()
            .map(FormTreeNode::Leaf)
            .collect::<Vec<_>>();
        while level.len() > 1 {
            let mut next_level = Vec::new();
            let mut child_cursor = 0usize;
            let children = level
                .iter()
                .map(|node| FormChild {
                    first_key: node.first_key().to_string(),
                    offset: node.offset(),
                })
                .collect::<Vec<_>>();
            for chunk in form_child_groups(&children)? {
                let (offset, object_id) = self.write_form_internal(chunk)?;
                let start = child_cursor;
                let end = start + chunk.len();
                child_cursor = end;
                let child_nodes = level[start..end].to_vec();
                next_level.push(FormTreeNode::Internal(FormInternal {
                    offset,
                    object_id,
                    children: child_nodes,
                }));
            }
            level = next_level;
        }
        Ok(level.remove(0))
    }

    fn rewrite_compatible_form_tree(
        &mut self,
        node: FormTreeNode,
        new_leaves: &[FormLeaf],
    ) -> Result<FormTreeNode> {
        match node {
            FormTreeNode::Leaf(old_leaf) => {
                let Some(new_leaf) = new_leaves
                    .iter()
                    .find(|leaf| leaf_first_key(leaf) == leaf_first_key(&old_leaf))
                    .cloned()
                else {
                    return Err(Error::CorruptRecord);
                };
                Ok(FormTreeNode::Leaf(new_leaf))
            }
            FormTreeNode::Internal(old_internal) => {
                let old_offset = old_internal.offset;
                let old_object_id = old_internal.object_id;
                let mut changed = false;
                let mut children = Vec::with_capacity(old_internal.children.len());
                for child in old_internal.children {
                    let child_offset = child.offset();
                    let child_first_key = child.first_key().to_string();
                    let rewritten = self.rewrite_compatible_form_tree(child, new_leaves)?;
                    if rewritten.offset() != child_offset
                        || rewritten.first_key() != child_first_key.as_str()
                    {
                        changed = true;
                    }
                    children.push(rewritten);
                }
                if !changed {
                    return Ok(FormTreeNode::Internal(FormInternal {
                        offset: old_offset,
                        object_id: old_object_id,
                        children,
                    }));
                }
                let form_children = children
                    .iter()
                    .map(|child| FormChild {
                        first_key: child.first_key().to_string(),
                        offset: child.offset(),
                    })
                    .collect::<Vec<_>>();
                let (offset, object_id) = self.write_form_internal(&form_children)?;
                Ok(FormTreeNode::Internal(FormInternal {
                    offset,
                    object_id,
                    children,
                }))
            }
        }
    }

    fn write_form_leaf(&mut self, entries: &[crate::form_btree::FormEntry]) -> Result<(u64, u64)> {
        let payload = encode_form_leaf_secure(entries)?;
        self.sequence += 1;
        let object_id = self.sequence;
        Ok((
            self.append_form_page_secure(PageObjectKind::FormLeaf, payload)?,
            object_id,
        ))
    }

    fn write_form_internal(&mut self, children: &[FormChild]) -> Result<(u64, u64)> {
        let payload = SecureVec::try_from_vec(encode_form_internal(children)?)?;
        self.sequence += 1;
        let object_id = self.sequence;
        Ok((
            self.append_form_page_secure(PageObjectKind::FormInternal, payload)?,
            object_id,
        ))
    }

    fn append_form_page_secure(
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
            )?;
        content_key.zeroize();
        payload.zeroize()?;
        Ok(page_offset)
    }
}

fn validated_definition(
    type_id: FormTypeId,
    alias: String,
    revision: u32,
    name: &str,
    fields: Vec<FormFieldDefinition>,
) -> Result<FormDefinition> {
    if fields.is_empty() {
        return Err(Error::InvalidInput(
            "form definition requires at least one field".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut validated_fields = Vec::with_capacity(fields.len());
    for field in fields {
        let id = validate_form_field_id(&field.id)?;
        if !seen.insert(id.clone()) {
            return Err(Error::InvalidInput(format!(
                "duplicate form field id: {id}"
            )));
        }
        validated_fields.push(FormFieldDefinition {
            id,
            label: validate_form_label(&field.label, "form field label")?,
            kind: field.kind,
            required: field.required,
        });
    }
    Ok(FormDefinition {
        type_id,
        alias,
        revision,
        name: validate_form_label(name, "form name")?,
        fields: validated_fields,
    })
}

fn leaf_first_key(leaf: &FormLeaf) -> &str {
    leaf.entries
        .first()
        .map(|entry| entry.key.as_str())
        .unwrap_or("")
}

fn form_leaf_directory_is_compatible(old: &[FormLeaf], new: &[FormLeaf]) -> bool {
    old.len() == new.len()
        && old
            .iter()
            .zip(new)
            .all(|(old, new)| leaf_first_key(old) == leaf_first_key(new))
}

fn form_entries_overlap_dirty(entries: &[FormEntry], dirty_keys: &BTreeSet<String>) -> bool {
    let Some(first) = entries.first().map(|entry| entry.key.as_str()) else {
        return false;
    };
    let last = entries
        .last()
        .map(|entry| entry.key.as_str())
        .unwrap_or(first);
    dirty_keys
        .iter()
        .any(|key| key.as_str() >= first && key.as_str() <= last)
}

fn collect_dirty_form_tree_redactions_from_node(
    node: &FormTreeNode,
    dirty_keys: &BTreeSet<String>,
    redactions: &mut Vec<(u64, u64)>,
) -> bool {
    match node {
        FormTreeNode::Leaf(leaf) => {
            let overlaps = form_entries_overlap_dirty(&leaf.entries, dirty_keys);
            if overlaps {
                redactions.push((leaf.offset, leaf.object_id));
            }
            overlaps
        }
        FormTreeNode::Internal(internal) => {
            let mut changed = false;
            for child in &internal.children {
                changed |=
                    collect_dirty_form_tree_redactions_from_node(child, dirty_keys, redactions);
            }
            if changed {
                redactions.push((internal.offset, internal.object_id));
            }
            changed
        }
    }
}
