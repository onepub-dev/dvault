use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    error::{Error, Result},
    memory_region,
};

pub(crate) const SIZE_CLASSES: &[usize] = &[64, 128, 256, 512, 1024, 2048, 4096];

const DEFAULT_ALLOCATION_CHUNK_BYTES: usize = 64 * 1024;

static ALLOCATION_CHUNK_BYTES: AtomicUsize = AtomicUsize::new(DEFAULT_ALLOCATION_CHUNK_BYTES);

pub fn allocation_chunk_bytes() -> usize {
    ALLOCATION_CHUNK_BYTES.load(Ordering::Relaxed)
}

pub fn set_allocation_chunk_bytes(bytes: usize) -> Result<()> {
    let page_size = memory_region::page_size();
    if bytes < page_size {
        return Err(Error::AllocationFailed);
    }
    let rounded = bytes
        .checked_add(page_size - 1)
        .map(|value| value / page_size * page_size)
        .ok_or(Error::CapacityOverflow)?;
    ALLOCATION_CHUNK_BYTES.store(rounded, Ordering::Relaxed);
    Ok(())
}
