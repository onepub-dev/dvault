use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FreeSlot {
    pub(crate) offset: u64,
    pub(crate) len: u64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FreeSpace {
    by_offset: BTreeMap<u64, u64>,
    by_len: BTreeMap<(u64, u64), ()>,
}

impl FreeSpace {
    pub(crate) fn add(&mut self, slot: FreeSlot) {
        if slot.len == 0 {
            return;
        }
        let mut start = slot.offset;
        let mut end = slot.offset.saturating_add(slot.len);

        if let Some((&prev_offset, &prev_len)) = self.by_offset.range(..=slot.offset).next_back() {
            let prev_end = prev_offset.saturating_add(prev_len);
            if prev_end >= start {
                self.remove_exact(prev_offset, prev_len);
                start = prev_offset;
                end = end.max(prev_end);
            }
        }

        while let Some((&next_offset, &next_len)) = self.by_offset.range(start..).next() {
            if next_offset > end {
                break;
            }
            self.remove_exact(next_offset, next_len);
            end = end.max(next_offset.saturating_add(next_len));
        }

        self.insert_exact(start, end - start);
    }

    pub(crate) fn allocate(&mut self, len: u64) -> Option<FreeSlot> {
        let (&(slot_len, offset), _) = self.by_len.range((len, 0)..).next()?;
        self.remove_exact(offset, slot_len);
        if slot_len > len {
            self.add(FreeSlot {
                offset: offset + len,
                len: slot_len - len,
            });
        }
        Some(FreeSlot { offset, len })
    }

    pub(crate) fn clear(&mut self) {
        self.by_offset.clear();
        self.by_len.clear();
    }

    pub(crate) fn slots_by_offset(&self) -> Vec<FreeSlot> {
        self.by_offset
            .iter()
            .map(|(&offset, &len)| FreeSlot { offset, len })
            .collect()
    }

    pub(crate) fn replace_slots(&mut self, slots: impl IntoIterator<Item = FreeSlot>) {
        self.clear();
        for slot in slots {
            self.add(slot);
        }
    }

    fn insert_exact(&mut self, offset: u64, len: u64) {
        self.by_offset.insert(offset, len);
        self.by_len.insert((len, offset), ());
    }

    fn remove_exact(&mut self, offset: u64, len: u64) {
        self.by_offset.remove(&offset);
        self.by_len.remove(&(len, offset));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_adjacent_and_overlapping_slots() {
        let mut free = FreeSpace::default();
        free.add(FreeSlot {
            offset: 200,
            len: 50,
        });
        free.add(FreeSlot {
            offset: 100,
            len: 100,
        });
        free.add(FreeSlot {
            offset: 240,
            len: 100,
        });

        assert_eq!(
            free.slots_by_offset(),
            vec![FreeSlot {
                offset: 100,
                len: 240
            }]
        );
    }

    #[test]
    fn allocates_best_fit_and_keeps_remainder() {
        let mut free = FreeSpace::default();
        free.add(FreeSlot {
            offset: 1_000,
            len: 1_000,
        });
        free.add(FreeSlot {
            offset: 5_000,
            len: 200,
        });

        assert_eq!(
            free.allocate(128),
            Some(FreeSlot {
                offset: 5_000,
                len: 128
            })
        );
        assert_eq!(
            free.slots_by_offset(),
            vec![
                FreeSlot {
                    offset: 1_000,
                    len: 1_000
                },
                FreeSlot {
                    offset: 5_128,
                    len: 72
                }
            ]
        );
    }
}
