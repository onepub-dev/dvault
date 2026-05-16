use crate::{
    allocation::Allocation,
    canary::CANARY_LEN,
    error::Result,
    memory_region::{MemoryRegion, Protection},
    page_permission::PagePermission,
};

pub(crate) struct Arena {
    memory: MemoryRegion,
    pub(crate) slot_size: usize,
    slot_stride: usize,
    slots: Vec<Slot>,
    free: Vec<usize>,
}

impl Arena {
    pub(crate) fn new(slot_size: usize, data_size: usize) -> Result<Self> {
        let memory = MemoryRegion::new(data_size)?;
        let slot_stride = Self::slot_stride(slot_size);
        let slot_count = data_size / slot_stride;
        let slots = (0..slot_count)
            .map(|_| Slot {
                generation: 0,
                live: false,
            })
            .collect::<Vec<_>>();
        let free = (0..slot_count).rev().collect::<Vec<_>>();
        Ok(Self {
            memory,
            slot_size,
            slot_stride,
            slots,
            free,
        })
    }

    pub(crate) fn required_data_size(slot_size: usize) -> usize {
        Self::slot_stride(slot_size)
    }

    pub(crate) fn allocate(&mut self, arena_index: usize) -> Option<Allocation> {
        let slot_index = self.free.pop()?;
        let slot = &mut self.slots[slot_index];
        slot.live = true;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        Some(Allocation {
            arena: arena_index,
            slot: slot_index,
            generation: slot.generation,
            offset: slot_index * self.slot_stride + CANARY_LEN,
            capacity: self.slot_size,
        })
    }

    pub(crate) fn free(&mut self, slot_index: usize) {
        let slot = &mut self.slots[slot_index];
        slot.live = false;
        self.free.push(slot_index);
    }

    pub(crate) fn ptr_for_offset(&self, offset: usize) -> *mut u8 {
        self.memory.data_ptr().wrapping_add(offset)
    }

    pub(crate) fn is_live_generation(&self, slot_index: usize, generation: u64) -> bool {
        self.slots
            .get(slot_index)
            .is_some_and(|slot| slot.live && slot.generation == generation)
    }

    pub(crate) fn protect_page(
        &mut self,
        page_index: usize,
        permission: PagePermission,
    ) -> Result<()> {
        let prot = match permission {
            PagePermission::Read => Protection::Read,
            PagePermission::Write => Protection::ReadWrite,
        };
        self.memory.protect_data_page(page_index, prot)
    }

    pub(crate) fn protect_page_none(&mut self, page_index: usize) -> Result<()> {
        self.memory.protect_data_page(page_index, Protection::None)
    }

    fn slot_stride(slot_size: usize) -> usize {
        slot_size + CANARY_LEN * 2
    }
}

struct Slot {
    generation: u64,
    live: bool,
}
