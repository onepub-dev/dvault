use std::collections::BTreeMap;
use std::sync::Arc;

use crate::checked::{read_u16_le, read_u32_le};
use crate::constants::DEFAULT_METADATA_MAX_PAGE_BODY_BYTES;
use crate::form::{
    validate_form_alias, validate_form_field_id, validate_form_label, validate_form_record_name,
    validate_form_value, FormDefinition, FormFieldDefinition, FormFieldKind, FormFieldValue,
    FormRecord, FormTypeId, FormValue,
};
use crate::page_tree::{
    decode_page_tree_children, encode_page_tree_children, group_by_encoded_size,
    page_tree_child_encoded_len, PageTreeChild,
};
use crate::secret_vec::{secure_read_access, SecureVec};
use crate::{Error, LockboxPath, Result, SecretString};

const FORM_NODE_VERSION: u8 = 1;
const FORM_LEAF: u8 = 1;
const FORM_INTERNAL: u8 = 2;
const FORM_NODE_PREFIX_BYTES: usize = 2;
const ENTRY_COUNT_BYTES: usize = 4;
const CHILD_COUNT_BYTES: usize = 4;
const ENTRY_DEFINITION: u8 = 1;
const ENTRY_RECORD: u8 = 2;
const VALUE_NORMAL: u8 = 0;
const VALUE_SECRET: u8 = 1;

#[derive(Debug, Clone)]
pub(crate) enum FormEntryValue {
    Definition(FormDefinition),
    Record(FormRecord),
}

#[derive(Debug, Clone)]
pub(crate) struct FormEntry {
    pub(crate) key: String,
    pub(crate) value: FormEntryValue,
}

#[derive(Debug)]
pub(crate) enum FormNode {
    Leaf(Vec<FormEntry>),
    Internal(Vec<FormChild>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FormChild {
    pub(crate) first_key: String,
    pub(crate) offset: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct FormLeaf {
    pub(crate) offset: u64,
    pub(crate) object_id: u64,
    pub(crate) entries: Vec<FormEntry>,
}

#[derive(Debug, Clone)]
pub(crate) struct FormInternal {
    pub(crate) offset: u64,
    pub(crate) object_id: u64,
    pub(crate) children: Vec<FormTreeNode>,
}

#[derive(Debug, Clone)]
pub(crate) enum FormTreeNode {
    Leaf(FormLeaf),
    Internal(FormInternal),
}

impl FormTreeNode {
    pub(crate) fn offset(&self) -> u64 {
        match self {
            Self::Leaf(leaf) => leaf.offset,
            Self::Internal(internal) => internal.offset,
        }
    }

    pub(crate) fn first_key(&self) -> &str {
        match self {
            Self::Leaf(leaf) => leaf
                .entries
                .first()
                .map(|entry| entry.key.as_str())
                .unwrap_or(""),
            Self::Internal(internal) => internal
                .children
                .first()
                .map(FormTreeNode::first_key)
                .unwrap_or(""),
        }
    }

    pub(crate) fn collect_leaves(&self, leaves: &mut Vec<FormLeaf>) {
        match self {
            Self::Leaf(leaf) => leaves.push(leaf.clone()),
            Self::Internal(internal) => {
                for child in &internal.children {
                    child.collect_leaves(leaves);
                }
            }
        }
    }
}

pub(crate) fn definition_key(type_id: &FormTypeId, revision: u32) -> String {
    format!("d/{}/{revision:010}", type_id.as_str())
}

pub(crate) fn record_key(path: &LockboxPath) -> String {
    format!("r{}", path.as_str())
}

pub(crate) fn form_entries_from_maps(
    definitions: &BTreeMap<String, FormDefinition>,
    records: &BTreeMap<LockboxPath, FormRecord>,
) -> Vec<FormEntry> {
    let mut entries = definitions
        .iter()
        .map(|(key, definition)| FormEntry {
            key: key.clone(),
            value: FormEntryValue::Definition(definition.clone()),
        })
        .collect::<Vec<_>>();
    entries.extend(records.iter().map(|(path, record)| FormEntry {
        key: record_key(path),
        value: FormEntryValue::Record(record.clone()),
    }));
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    entries
}

pub(crate) fn encode_form_leaf_secure(entries: &[FormEntry]) -> Result<SecureVec> {
    let mut out = SecureVec::new();
    out.try_extend_from_slice(&[FORM_NODE_VERSION, FORM_LEAF])?;
    out.try_extend_from_slice(&(entries.len() as u32).to_le_bytes())?;
    for entry in entries {
        put_string_secure(&mut out, &entry.key)?;
        match &entry.value {
            FormEntryValue::Definition(definition) => {
                out.try_extend_from_slice(&[ENTRY_DEFINITION])?;
                encode_definition_secure(&mut out, definition)?;
            }
            FormEntryValue::Record(record) => {
                out.try_extend_from_slice(&[ENTRY_RECORD])?;
                encode_record_secure(&mut out, record)?;
            }
        }
    }
    if out.len() > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "form leaf exceeds maximum page size".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn encode_form_internal(children: &[FormChild]) -> Result<Vec<u8>> {
    let routing_children = children
        .iter()
        .map(|child| PageTreeChild {
            first_key: child.first_key.clone(),
            offset: child.offset,
        })
        .collect::<Vec<_>>();
    let mut out = Vec::new();
    out.push(FORM_NODE_VERSION);
    out.push(FORM_INTERNAL);
    out.extend_from_slice(&encode_page_tree_children(&routing_children));
    if out.len() > DEFAULT_METADATA_MAX_PAGE_BODY_BYTES {
        return Err(Error::SecurityLimitExceeded(
            "form internal node exceeds maximum page size".to_string(),
        ));
    }
    Ok(out)
}

pub(crate) fn form_leaf_groups(entries: &[FormEntry]) -> Result<Vec<&[FormEntry]>> {
    group_by_encoded_size(
        entries,
        FORM_NODE_PREFIX_BYTES + ENTRY_COUNT_BYTES,
        form_entry_encoded_len,
        "form entry",
    )
}

pub(crate) fn form_child_groups(children: &[FormChild]) -> Result<Vec<&[FormChild]>> {
    group_by_encoded_size(
        children,
        FORM_NODE_PREFIX_BYTES + CHILD_COUNT_BYTES,
        form_child_encoded_len,
        "form child",
    )
}

pub(crate) fn decode_form_node_secure(payload: &SecureVec) -> Result<FormNode> {
    let parsed = secure_read_access(|access| {
        payload.with_bytes_in(access, |payload| {
            if payload.len() < FORM_NODE_PREFIX_BYTES || payload[0] != FORM_NODE_VERSION {
                return Err(Error::CorruptRecord);
            }
            match payload[1] {
                FORM_LEAF => decode_form_leaf_metadata(payload),
                FORM_INTERNAL => Ok(ParsedFormNode::Internal(
                    decode_page_tree_children(&payload[2..], validate_form_tree_key)?
                        .into_iter()
                        .map(|child| FormChild {
                            first_key: child.first_key,
                            offset: child.offset,
                        })
                        .collect(),
                )),
                _ => Err(Error::CorruptRecord),
            }
        })
    })??;
    match parsed {
        ParsedFormNode::Internal(children) => Ok(FormNode::Internal(children)),
        ParsedFormNode::Leaf(entries) => {
            let mut decoded = Vec::with_capacity(entries.len());
            for entry in entries {
                decoded.push(FormEntry {
                    key: entry.key,
                    value: match entry.value {
                        ParsedFormEntryValue::Definition(definition) => {
                            FormEntryValue::Definition(definition)
                        }
                        ParsedFormEntryValue::Record(record) => {
                            FormEntryValue::Record(materialize_record(payload, record)?)
                        }
                    },
                });
            }
            Ok(FormNode::Leaf(decoded))
        }
    }
}

enum ParsedFormNode {
    Leaf(Vec<ParsedFormEntry>),
    Internal(Vec<FormChild>),
}

struct ParsedFormEntry {
    key: String,
    value: ParsedFormEntryValue,
}

enum ParsedFormEntryValue {
    Definition(FormDefinition),
    Record(ParsedFormRecord),
}

struct ParsedFormRecord {
    path: LockboxPath,
    name: String,
    type_id: FormTypeId,
    definition_alias: String,
    definition_revision: u32,
    values: Vec<ParsedFormFieldValue>,
}

struct ParsedFormFieldValue {
    field_id: String,
    captured_label: String,
    kind: FormFieldKind,
    value: ParsedFormValue,
}

enum ParsedFormValue {
    Normal(String),
    Secret { offset: usize, len: usize },
}

fn decode_form_leaf_metadata(payload: &[u8]) -> Result<ParsedFormNode> {
    if payload.len() < FORM_NODE_PREFIX_BYTES + ENTRY_COUNT_BYTES {
        return Err(Error::CorruptRecord);
    }
    let mut reader = Reader::new(&payload[FORM_NODE_PREFIX_BYTES..]);
    let count = reader.u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let key = reader.string()?;
        validate_form_tree_key(&key)?;
        let tag = reader.u8()?;
        let value = match tag {
            ENTRY_DEFINITION => ParsedFormEntryValue::Definition(decode_definition(&mut reader)?),
            ENTRY_RECORD => ParsedFormEntryValue::Record(decode_record(&mut reader)?),
            _ => return Err(Error::CorruptRecord),
        };
        entries.push(ParsedFormEntry { key, value });
    }
    reader.done()?;
    for pair in entries.windows(2) {
        if pair[0].key >= pair[1].key {
            return Err(Error::CorruptRecord);
        }
    }
    Ok(ParsedFormNode::Leaf(entries))
}

fn materialize_record(payload: &SecureVec, parsed: ParsedFormRecord) -> Result<FormRecord> {
    let mut values = Vec::with_capacity(parsed.values.len());
    for value in parsed.values {
        let form_value = match value.value {
            ParsedFormValue::Normal(value) => FormValue::Normal(value),
            ParsedFormValue::Secret { offset, len } => {
                let bytes = payload.try_clone_range(offset, len)?;
                FormValue::Secret(Arc::new(SecretString::from_secure_vec(bytes)))
            }
        };
        validate_form_value(value.kind, &form_value)?;
        values.push(FormFieldValue {
            field_id: value.field_id,
            captured_label: value.captured_label,
            kind: value.kind,
            value: form_value,
        });
    }
    Ok(FormRecord {
        path: parsed.path,
        name: parsed.name,
        type_id: parsed.type_id,
        definition_alias: parsed.definition_alias,
        definition_revision: parsed.definition_revision,
        values,
    })
}

fn encode_definition_secure(out: &mut SecureVec, definition: &FormDefinition) -> Result<()> {
    put_string_secure(out, definition.type_id.as_str())?;
    put_string_secure(out, &definition.alias)?;
    out.try_extend_from_slice(&definition.revision.to_le_bytes())?;
    put_string_secure(out, &definition.name)?;
    out.try_extend_from_slice(&(definition.fields.len() as u32).to_le_bytes())?;
    for field in &definition.fields {
        put_string_secure(out, &field.id)?;
        put_string_secure(out, &field.label)?;
        out.try_extend_from_slice(&[field.kind.code(), u8::from(field.required)])?;
    }
    Ok(())
}

fn decode_definition(reader: &mut Reader<'_>) -> Result<FormDefinition> {
    let type_id = FormTypeId::new(reader.string()?)?;
    let alias = validate_form_alias(&reader.string()?)?;
    let revision = reader.u32()?;
    if revision == 0 {
        return Err(Error::CorruptRecord);
    }
    let name = validate_form_label(&reader.string()?, "form name")?;
    let count = reader.u32()? as usize;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        fields.push(FormFieldDefinition {
            id: validate_form_field_id(&reader.string()?)?,
            label: validate_form_label(&reader.string()?, "form field label")?,
            kind: FormFieldKind::from_code(reader.u8()?)?,
            required: match reader.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Error::CorruptRecord),
            },
        });
    }
    Ok(FormDefinition {
        type_id,
        alias,
        revision,
        name,
        fields,
    })
}

fn encode_record_secure(out: &mut SecureVec, record: &FormRecord) -> Result<()> {
    put_string_secure(out, record.path.as_str())?;
    put_string_secure(out, &record.name)?;
    put_string_secure(out, record.type_id.as_str())?;
    put_string_secure(out, &record.definition_alias)?;
    out.try_extend_from_slice(&record.definition_revision.to_le_bytes())?;
    out.try_extend_from_slice(&(record.values.len() as u32).to_le_bytes())?;
    for value in &record.values {
        put_string_secure(out, &value.field_id)?;
        put_string_secure(out, &value.captured_label)?;
        out.try_extend_from_slice(&[value.kind.code()])?;
        match &value.value {
            FormValue::Normal(value) => {
                out.try_extend_from_slice(&[VALUE_NORMAL])?;
                put_string_secure(out, value)?;
            }
            FormValue::Secret(value) => {
                out.try_extend_from_slice(&[VALUE_SECRET])?;
                let len = value.with_str(str::len)?;
                out.try_extend_from_slice(&(len as u32).to_le_bytes())?;
                value.append_to_secure_vec(out)?;
            }
        }
    }
    Ok(())
}

fn decode_record(reader: &mut Reader<'_>) -> Result<ParsedFormRecord> {
    let path = LockboxPath::new(reader.string()?)?;
    let name = validate_form_record_name(&reader.string()?)?;
    let type_id = FormTypeId::new(reader.string()?)?;
    let definition_alias = validate_form_alias(&reader.string()?)?;
    let definition_revision = reader.u32()?;
    if definition_revision == 0 {
        return Err(Error::CorruptRecord);
    }
    let count = reader.u32()? as usize;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let field_id = validate_form_field_id(&reader.string()?)?;
        let captured_label = validate_form_label(&reader.string()?, "form field label")?;
        let kind = FormFieldKind::from_code(reader.u8()?)?;
        let value = match reader.u8()? {
            VALUE_NORMAL => ParsedFormValue::Normal(reader.string()?),
            VALUE_SECRET => {
                let (offset, len) = reader.bytes_range()?;
                ParsedFormValue::Secret { offset, len }
            }
            _ => return Err(Error::CorruptRecord),
        };
        values.push(ParsedFormFieldValue {
            field_id,
            captured_label,
            kind,
            value,
        });
    }
    Ok(ParsedFormRecord {
        path,
        name,
        type_id,
        definition_alias,
        definition_revision,
        values,
    })
}

fn validate_form_tree_key(key: &str) -> Result<()> {
    if let Some(rest) = key.strip_prefix("d/") {
        let Some((type_id, revision)) = rest.split_once('/') else {
            return Err(Error::CorruptRecord);
        };
        FormTypeId::new(type_id)?;
        if revision.len() != 10 || !revision.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(Error::CorruptRecord);
        }
        return Ok(());
    }
    if let Some(path) = key.strip_prefix('r') {
        LockboxPath::new(path)?;
        return Ok(());
    }
    Err(Error::CorruptRecord)
}

fn put_string_secure(out: &mut SecureVec, value: &str) -> Result<()> {
    out.try_extend_from_slice(&(value.len() as u16).to_le_bytes())?;
    out.try_extend_from_slice(value.as_bytes())?;
    Ok(())
}

fn form_entry_encoded_len(entry: &FormEntry) -> usize {
    2 + entry.key.len()
        + 1
        + match &entry.value {
            FormEntryValue::Definition(definition) => definition_encoded_len(definition),
            FormEntryValue::Record(record) => record_encoded_len(record),
        }
}

fn definition_encoded_len(definition: &FormDefinition) -> usize {
    2 + definition.type_id.as_str().len()
        + 2
        + definition.alias.len()
        + 4
        + 2
        + definition.name.len()
        + 4
        + definition
            .fields
            .iter()
            .map(|field| 2 + field.id.len() + 2 + field.label.len() + 2)
            .sum::<usize>()
}

fn record_encoded_len(record: &FormRecord) -> usize {
    2 + record.path.as_str().len()
        + 2
        + record.name.len()
        + 2
        + record.type_id.as_str().len()
        + 2
        + record.definition_alias.len()
        + 4
        + 4
        + record
            .values
            .iter()
            .map(|value| {
                2 + value.field_id.len()
                    + 2
                    + value.captured_label.len()
                    + 1
                    + 1
                    + match &value.value {
                        FormValue::Normal(value) => 2 + value.len(),
                        FormValue::Secret(value) => {
                            4 + value
                                .with_str(str::len)
                                .unwrap_or(DEFAULT_METADATA_MAX_PAGE_BODY_BYTES)
                        }
                    }
            })
            .sum::<usize>()
}

fn form_child_encoded_len(child: &FormChild) -> usize {
    page_tree_child_encoded_len(&PageTreeChild {
        first_key: child.first_key.clone(),
        offset: child.offset,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn u8(&mut self) -> Result<u8> {
        if self.offset >= self.bytes.len() {
            return Err(Error::CorruptRecord);
        }
        let value = self.bytes[self.offset];
        self.offset += 1;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32> {
        if self.offset + 4 > self.bytes.len() {
            return Err(Error::CorruptRecord);
        }
        let value = read_u32_le(&self.bytes[self.offset..self.offset + 4])?;
        self.offset += 4;
        Ok(value)
    }

    fn string(&mut self) -> Result<String> {
        let len = self.string_len()?;
        if self.offset + len > self.bytes.len() {
            return Err(Error::CorruptRecord);
        }
        let value = std::str::from_utf8(&self.bytes[self.offset..self.offset + len])
            .map_err(|_| Error::CorruptRecord)?
            .to_string();
        self.offset += len;
        Ok(value)
    }

    fn bytes_range(&mut self) -> Result<(usize, usize)> {
        if self.offset + 4 > self.bytes.len() {
            return Err(Error::CorruptRecord);
        }
        let len = read_u32_le(&self.bytes[self.offset..self.offset + 4])? as usize;
        self.offset += 4;
        if self.offset + len > self.bytes.len() {
            return Err(Error::CorruptRecord);
        }
        let offset = self.offset;
        self.offset += len;
        Ok((offset + FORM_NODE_PREFIX_BYTES, len))
    }

    fn string_len(&mut self) -> Result<usize> {
        if self.offset + 2 > self.bytes.len() {
            return Err(Error::CorruptRecord);
        }
        let len = read_u16_le(&self.bytes[self.offset..self.offset + 2])? as usize;
        self.offset += 2;
        Ok(len)
    }

    fn done(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::CorruptRecord)
        }
    }
}
