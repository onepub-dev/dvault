use std::collections::BTreeMap;

use super::Lockbox;
use crate::env_btree::{
    decode_env_node, encode_env_internal, encode_env_leaf, env_child_groups, env_entries_from_map,
    env_leaf_groups, EnvChild, EnvInternal, EnvLeaf, EnvNode, EnvTreeNode,
};
use crate::free_slot::FreeSlot;
use crate::page::{page_size_for_objects, PageObject, PageObjectKind};
use crate::security::{validate_env_name, validate_env_value};
use crate::{Error, Result};

impl Lockbox {
    pub fn set_env(&mut self, name: &str, value: &str) -> Result<()> {
        let name = validate_env_name(name)?;
        let value = validate_env_value(value)?;
        self.ensure_env_loaded()?;
        self.env_vars
            .borrow_mut()
            .as_mut()
            .ok_or(Error::CorruptRecord)?
            .insert(name, value);
        self.dirty_env = true;
        Ok(())
    }

    pub fn get_env(&self, name: &str) -> Result<Option<String>> {
        let name = validate_env_name(name)?;
        self.ensure_env_loaded()?;
        Ok(self
            .env_vars
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .get(name.as_str())
            .cloned())
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

    pub fn get_all_env(&self) -> Result<BTreeMap<String, String>> {
        self.ensure_env_loaded()?;
        Ok(self
            .env_vars
            .borrow()
            .as_ref()
            .ok_or(Error::CorruptRecord)?
            .clone())
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
            let object = PageObject {
                kind: PageObjectKind::EnvLeaf,
                id: object_id,
                payload: encode_env_leaf(&[])?,
            };
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
    ) -> Result<(BTreeMap<String, String>, EnvTreeNode, Vec<EnvLeaf>)> {
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
        env: &mut BTreeMap<String, String>,
        depth: usize,
    ) -> Result<EnvTreeNode> {
        if depth > 8 {
            return Err(Error::CorruptRecord);
        }
        match decode_env_node(&self.read_env_node_payload(offset)?)? {
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

    fn read_env_node_payload(&self, offset: u64) -> Result<Vec<u8>> {
        let decoded = self.read_page(offset)?;
        let Some(env_object) = decoded.objects.iter().find(|object| {
            matches!(
                object.kind,
                PageObjectKind::EnvLeaf | PageObjectKind::EnvInternal
            )
        }) else {
            return Err(Error::CorruptRecord);
        };
        Ok(env_object.payload.clone())
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
        let decoded = self.read_page(offset)?;
        let Some(env_object) = decoded.objects.iter().find(|object| {
            matches!(
                object.kind,
                PageObjectKind::EnvLeaf | PageObjectKind::EnvInternal
            )
        }) else {
            return Err(Error::CorruptRecord);
        };
        redactions.push((offset, env_object.id));
        if env_object.kind == PageObjectKind::EnvInternal {
            let EnvNode::Internal(children) = decode_env_node(&env_object.payload)? else {
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
        let payload = encode_env_leaf(entries)?;
        self.sequence += 1;
        self.append_env_page(PageObjectKind::EnvLeaf, payload)
    }

    fn write_env_internal(&mut self, children: &[EnvChild]) -> Result<u64> {
        let payload = encode_env_internal(children)?;
        self.sequence += 1;
        self.append_env_page(PageObjectKind::EnvInternal, payload)
    }

    fn append_env_page(&mut self, kind: PageObjectKind, payload: Vec<u8>) -> Result<u64> {
        let object = PageObject {
            kind,
            id: self.sequence,
            payload,
        };
        let page_offset =
            self.allocate_page_offset(page_size_for_objects(std::slice::from_ref(&object)) as u64)?;
        self.write_decoded_page_at(page_offset, self.sequence, vec![object])?;
        Ok(page_offset)
    }
}
