use crate::checked::{read_u32_le, read_u64_le};
use crate::free_slot::FreeSlot;
use crate::{Error, Result};

const FREE_INDEX_VERSION: u8 = 1;
#[cfg(not(test))]
pub(crate) const FREE_INDEX_LEAF_SLOT_CAPACITY: usize = 500_000;
#[cfg(test)]
pub(crate) const FREE_INDEX_LEAF_SLOT_CAPACITY: usize = 8;
#[cfg(not(test))]
pub(crate) const FREE_INDEX_INTERNAL_CHILD_CAPACITY: usize = 500_000;
#[cfg(test)]
pub(crate) const FREE_INDEX_INTERNAL_CHILD_CAPACITY: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FreeIndexChild {
    pub(crate) first_offset: u64,
    pub(crate) offset: u64,
}

pub(crate) fn free_index_leaf_groups(slots: &[FreeSlot]) -> impl Iterator<Item = &[FreeSlot]> {
    slots.chunks(FREE_INDEX_LEAF_SLOT_CAPACITY.max(1))
}

pub(crate) fn free_index_child_groups(
    children: &[FreeIndexChild],
) -> impl Iterator<Item = &[FreeIndexChild]> {
    children.chunks(FREE_INDEX_INTERNAL_CHILD_CAPACITY.max(1))
}

pub(crate) fn encode_free_index_leaf(slots: &[FreeSlot]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + slots.len() * 16);
    out.push(FREE_INDEX_VERSION);
    out.push(0);
    out.push(0);
    out.push(0);
    out.extend_from_slice(&(slots.len() as u32).to_le_bytes());
    for slot in slots {
        out.extend_from_slice(&slot.offset.to_le_bytes());
        out.extend_from_slice(&slot.len.to_le_bytes());
    }
    out
}

pub(crate) fn encode_free_index_internal(children: &[FreeIndexChild]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + children.len() * 16);
    out.push(FREE_INDEX_VERSION);
    out.push(1);
    out.extend_from_slice(&[0; 2]);
    out.extend_from_slice(&(children.len() as u32).to_le_bytes());
    for child in children {
        out.extend_from_slice(&child.first_offset.to_le_bytes());
        out.extend_from_slice(&child.offset.to_le_bytes());
    }
    out
}

pub(crate) fn decode_free_index_leaf(payload: &[u8]) -> Result<Vec<FreeSlot>> {
    if payload.len() < 8 || payload[0] != FREE_INDEX_VERSION {
        return Err(Error::CorruptRecord);
    }
    if payload[1] != 0 || payload[2..4].iter().any(|byte| *byte != 0) {
        return Err(Error::CorruptRecord);
    }
    let count = read_u32_le(&payload[4..8])? as usize;
    let expected_len = 8usize
        .checked_add(count.checked_mul(16).ok_or(Error::CorruptRecord)?)
        .ok_or(Error::CorruptRecord)?;
    if payload.len() != expected_len {
        return Err(Error::CorruptRecord);
    }
    let mut offset = 8usize;
    let mut slots = Vec::with_capacity(count);
    let mut previous_end = 0u64;
    for index in 0..count {
        let slot_offset = read_u64_le(&payload[offset..offset + 8])?;
        let slot_len = read_u64_le(&payload[offset + 8..offset + 16])?;
        offset += 16;
        if slot_len == 0 {
            return Err(Error::CorruptRecord);
        }
        if index > 0 && slot_offset < previous_end {
            return Err(Error::CorruptRecord);
        }
        previous_end = slot_offset
            .checked_add(slot_len)
            .ok_or(Error::CorruptRecord)?;
        slots.push(FreeSlot {
            offset: slot_offset,
            len: slot_len,
        });
    }
    Ok(slots)
}

pub(crate) fn decode_free_index_internal(payload: &[u8]) -> Result<Vec<FreeIndexChild>> {
    if payload.len() < 8 || payload[0] != FREE_INDEX_VERSION {
        return Err(Error::CorruptRecord);
    }
    if payload[1] != 1 || payload[2..4].iter().any(|byte| *byte != 0) {
        return Err(Error::CorruptRecord);
    }
    let count = read_u32_le(&payload[4..8])? as usize;
    let expected_len = 8usize
        .checked_add(count.checked_mul(16).ok_or(Error::CorruptRecord)?)
        .ok_or(Error::CorruptRecord)?;
    if payload.len() != expected_len || count == 0 {
        return Err(Error::CorruptRecord);
    }
    let mut offset = 8usize;
    let mut children = Vec::with_capacity(count);
    let mut previous_first = None;
    for _ in 0..count {
        let first_offset = read_u64_le(&payload[offset..offset + 8])?;
        let child_offset = read_u64_le(&payload[offset + 8..offset + 16])?;
        offset += 16;
        if child_offset == 0 || previous_first.is_some_and(|previous| first_offset <= previous) {
            return Err(Error::CorruptRecord);
        }
        previous_first = Some(first_offset);
        children.push(FreeIndexChild {
            first_offset,
            offset: child_offset,
        });
    }
    Ok(children)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_index_round_trips_slots() {
        let slots = vec![
            FreeSlot {
                offset: 100,
                len: 20,
            },
            FreeSlot {
                offset: 200,
                len: 40,
            },
        ];

        assert_eq!(
            decode_free_index_leaf(&encode_free_index_leaf(&slots)).unwrap(),
            slots
        );
    }

    #[test]
    fn free_index_rejects_overlapping_slots() {
        let payload = encode_free_index_leaf(&[
            FreeSlot {
                offset: 100,
                len: 100,
            },
            FreeSlot {
                offset: 150,
                len: 10,
            },
        ]);

        assert!(matches!(
            decode_free_index_leaf(&payload),
            Err(Error::CorruptRecord)
        ));
    }

    #[test]
    fn free_index_internal_round_trips_children() {
        let children = vec![
            FreeIndexChild {
                first_offset: 100,
                offset: 1_000,
            },
            FreeIndexChild {
                first_offset: 200,
                offset: 2_000,
            },
        ];

        assert_eq!(
            decode_free_index_internal(&encode_free_index_internal(&children)).unwrap(),
            children
        );
    }
}
