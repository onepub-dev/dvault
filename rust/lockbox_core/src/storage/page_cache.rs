use crate::cache_options::{cache_limit_bytes, CacheLimit, CacheStats};
use crate::fast_hash::FastBuildHasher;
use crate::lockbox_id::LockboxId;
use crate::page::{
    decode_page, encode_page, page_size_for_objects, DecodedPage, PAGE_HEADER_LEN, PAGE_MAGIC,
};
use crate::storage::Storage;
use crate::{Error, Result};
use std::collections::{BTreeSet, HashMap, VecDeque};

const AUTO_RESIZE_INTERVAL: u64 = 1024;

#[derive(Debug, Clone)]
pub(crate) struct PageCache {
    limit: CacheLimit,
    limit_bytes: u64,
    used_bytes: u64,
    pages: HashMap<u64, CachedPage, FastBuildHasher>,
    dirty_offsets: BTreeSet<u64>,
    discard_after_flush: BTreeSet<u64>,
    zeroed_pages: HashMap<u64, u64, FastBuildHasher>,
    recent: VecDeque<u64>,
    hits: u64,
    misses: u64,
    operations_since_resize: u64,
}

#[derive(Debug, Clone)]
struct CachedPage {
    page: DecodedPage,
    weight: u64,
    generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageWritePolicy {
    RetainAfterFlush,
    DiscardAfterFlush,
}

impl PageCache {
    pub(crate) fn new(limit: CacheLimit) -> Self {
        Self {
            limit,
            limit_bytes: cache_limit_bytes(limit),
            used_bytes: 0,
            pages: HashMap::with_hasher(FastBuildHasher::default()),
            dirty_offsets: BTreeSet::new(),
            discard_after_flush: BTreeSet::new(),
            zeroed_pages: HashMap::with_hasher(FastBuildHasher::default()),
            recent: VecDeque::new(),
            hits: 0,
            misses: 0,
            operations_since_resize: 0,
        }
    }

    pub(crate) fn read_decoded_page_from_storage(
        storage: &impl Storage,
        offset: u64,
        lockbox_id: LockboxId,
        key: &[u8],
    ) -> Result<DecodedPage> {
        let header = storage.read_at(offset, PAGE_HEADER_LEN)?;
        if header.get(0..8) != Some(PAGE_MAGIC.as_slice()) {
            return Err(Error::CorruptRecord);
        }
        let header_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
        let stored_body_len = u32::from_le_bytes(header[44..48].try_into().unwrap()) as usize;
        let read_len = header_len
            .checked_add(stored_body_len)
            .ok_or(Error::CorruptRecord)?;
        let bytes = storage.read_at(offset, read_len)?;
        decode_page(&bytes, lockbox_id, key)
    }

    pub(crate) fn stage_decoded_page(
        &mut self,
        offset: u64,
        page_size: usize,
        page: DecodedPage,
    ) -> Result<()> {
        self.stage_decoded_page_with_policy(
            offset,
            page_size,
            page,
            PageWritePolicy::RetainAfterFlush,
        )
    }

    pub(crate) fn stage_decoded_page_with_policy(
        &mut self,
        offset: u64,
        page_size: usize,
        page: DecodedPage,
        policy: PageWritePolicy,
    ) -> Result<()> {
        self.zeroed_pages.remove(&offset);
        match policy {
            PageWritePolicy::RetainAfterFlush => {
                self.discard_after_flush.remove(&offset);
            }
            PageWritePolicy::DiscardAfterFlush => {
                self.discard_after_flush.insert(offset);
            }
        }
        self.insert_dirty_page(offset, page, page_size as u64);
        Ok(())
    }

    pub(crate) fn stage_zeroed_page(&mut self, offset: u64, page_size: u64) {
        self.evict(offset);
        self.dirty_offsets.remove(&offset);
        self.discard_after_flush.remove(&offset);
        self.zeroed_pages.insert(offset, page_size);
    }

    pub(crate) fn flush_dirty_pages(
        &mut self,
        storage: &mut impl Storage,
        lockbox_id: LockboxId,
        key: &[u8],
    ) -> Result<()> {
        let dirty_offsets = self.dirty_offsets.iter().copied().collect::<Vec<_>>();
        self.flush_dirty_offsets(storage, lockbox_id, key, dirty_offsets)?;
        self.flush_zeroed_pages(storage)
    }

    pub(crate) fn flush_discardable_pages(
        &mut self,
        storage: &mut impl Storage,
        lockbox_id: LockboxId,
        key: &[u8],
    ) -> Result<()> {
        let dirty_offsets = self.discard_after_flush.iter().copied().collect::<Vec<_>>();
        self.flush_dirty_offsets(storage, lockbox_id, key, dirty_offsets)
    }

    fn flush_dirty_offsets(
        &mut self,
        storage: &mut impl Storage,
        lockbox_id: LockboxId,
        key: &[u8],
        dirty_offsets: Vec<u64>,
    ) -> Result<()> {
        let mut storage_len = storage.len()?;
        for offset in dirty_offsets {
            if !self.dirty_offsets.contains(&offset) {
                self.discard_after_flush.remove(&offset);
                continue;
            }
            let (encoded, page_size) = {
                let entry = self.pages.get(&offset).ok_or(crate::Error::CorruptRecord)?;
                let page_size = usize::try_from(entry.weight).map_err(|_| {
                    crate::Error::SecurityLimitExceeded(
                        "page size exceeds addressable memory".to_string(),
                    )
                })?;
                let encoded = encode_page(
                    page_size,
                    lockbox_id,
                    entry.page.page_id,
                    entry.page.sequence,
                    key,
                    &entry.page.objects,
                )?;
                (encoded, page_size)
            };
            while offset > storage_len {
                let gap = offset.saturating_sub(storage_len);
                let fill_len = usize::try_from(gap.min(page_size as u64)).map_err(|_| {
                    crate::Error::SecurityLimitExceeded(
                        "page gap exceeds addressable memory".to_string(),
                    )
                })?;
                let fill = vec![0; fill_len];
                let appended = storage.append(&fill)?;
                if appended != storage_len {
                    return Err(crate::Error::CorruptRecord);
                }
                storage_len = storage_len.saturating_add(fill_len as u64);
            }
            if offset == storage_len {
                let appended = storage.append(&encoded)?;
                if appended != offset {
                    return Err(crate::Error::CorruptRecord);
                }
                storage_len = storage_len.saturating_add(encoded.len() as u64);
            } else {
                storage.write_at(offset, &encoded)?;
            }
            self.dirty_offsets.remove(&offset);
            if self.limit_bytes == 0 || self.discard_after_flush.remove(&offset) {
                self.evict(offset);
            }
        }
        Ok(())
    }

    fn flush_zeroed_pages(&mut self, storage: &mut impl Storage) -> Result<()> {
        let storage_len = storage.len()?;
        let zeroed_pages = self
            .zeroed_pages
            .iter()
            .map(|(&offset, &page_size)| (offset, page_size))
            .collect::<Vec<_>>();
        for (offset, page_size) in zeroed_pages {
            if offset.saturating_add(page_size) > storage_len {
                self.zeroed_pages.remove(&offset);
                continue;
            }
            let zero_len = usize::try_from(page_size).map_err(|_| {
                crate::Error::SecurityLimitExceeded(
                    "page length exceeds addressable memory".to_string(),
                )
            })?;
            storage.write_at(offset, &vec![0; zero_len])?;
            self.zeroed_pages.remove(&offset);
        }
        Ok(())
    }

    pub(crate) fn virtual_len(&self, storage_len: u64) -> u64 {
        self.dirty_offsets
            .iter()
            .filter_map(|offset| {
                self.pages
                    .get(offset)
                    .map(|page| offset.saturating_add(page.weight))
            })
            .max()
            .unwrap_or(storage_len)
            .max(storage_len)
    }

    pub(crate) fn has_dirty_pages(&self) -> bool {
        !self.dirty_offsets.is_empty() || !self.zeroed_pages.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) fn get_page(&mut self, offset: u64) -> Option<DecodedPage> {
        self.refresh_limit_if_needed();
        if self.zeroed_pages.contains_key(&offset) {
            self.misses = self.misses.saturating_add(1);
            return None;
        }
        let Some(entry) = self.pages.get_mut(&offset) else {
            self.misses = self.misses.saturating_add(1);
            return None;
        };
        self.hits = self.hits.saturating_add(1);
        entry.generation = entry.generation.saturating_add(1);
        self.recent.push_back(offset);
        Some(entry.page.clone())
    }

    pub(crate) fn with_page<R>(
        &mut self,
        offset: u64,
        f: impl FnOnce(&DecodedPage) -> R,
    ) -> Option<R> {
        self.refresh_limit_if_needed();
        if self.zeroed_pages.contains_key(&offset) {
            self.misses = self.misses.saturating_add(1);
            return None;
        }
        let Some(entry) = self.pages.get_mut(&offset) else {
            self.misses = self.misses.saturating_add(1);
            return None;
        };
        self.hits = self.hits.saturating_add(1);
        entry.generation = entry.generation.saturating_add(1);
        self.recent.push_back(offset);
        Some(f(&entry.page))
    }

    #[allow(dead_code)]
    pub(crate) fn with_page_mut<R>(
        &mut self,
        offset: u64,
        f: impl FnOnce(&mut DecodedPage) -> R,
    ) -> Option<R> {
        self.refresh_limit_if_needed();
        if self.zeroed_pages.contains_key(&offset) {
            self.misses = self.misses.saturating_add(1);
            return None;
        }
        let Some(entry) = self.pages.get_mut(&offset) else {
            self.misses = self.misses.saturating_add(1);
            return None;
        };
        self.hits = self.hits.saturating_add(1);
        entry.generation = entry.generation.saturating_add(1);
        self.recent.push_back(offset);
        let old_weight = entry.weight;
        let result = f(&mut entry.page);
        let new_weight = page_size_for_objects(&entry.page.objects) as u64;
        entry.weight = new_weight;
        self.used_bytes = self
            .used_bytes
            .saturating_sub(old_weight)
            .saturating_add(new_weight);
        self.dirty_offsets.insert(offset);
        Some(result)
    }

    pub(crate) fn insert_page(&mut self, offset: u64, page: DecodedPage, weight: u64) {
        self.zeroed_pages.remove(&offset);
        self.discard_after_flush.remove(&offset);
        self.insert_page_with_policy(offset, page, weight, false);
    }

    fn insert_dirty_page(&mut self, offset: u64, page: DecodedPage, weight: u64) {
        self.dirty_offsets.insert(offset);
        self.insert_page_with_policy(offset, page, weight, true);
    }

    fn insert_page_with_policy(
        &mut self,
        offset: u64,
        page: DecodedPage,
        weight: u64,
        force: bool,
    ) {
        self.refresh_limit_if_needed();
        if !force && (self.limit_bytes == 0 || weight > self.limit_bytes) {
            return;
        }
        if let Some(old) = self.pages.remove(&offset) {
            self.used_bytes = self.used_bytes.saturating_sub(old.weight);
        }
        self.used_bytes = self.used_bytes.saturating_add(weight);
        self.pages.insert(
            offset,
            CachedPage {
                page,
                weight,
                generation: 0,
            },
        );
        self.recent.push_back(offset);
        self.trim_to_limit();
    }

    pub(crate) fn clear(&mut self) {
        self.used_bytes = 0;
        self.pages.clear();
        self.dirty_offsets.clear();
        self.discard_after_flush.clear();
        self.zeroed_pages.clear();
        self.recent.clear();
    }

    pub(crate) fn evict(&mut self, offset: u64) {
        if let Some(old) = self.pages.remove(&offset) {
            self.used_bytes = self.used_bytes.saturating_sub(old.weight);
        }
        self.dirty_offsets.remove(&offset);
        self.discard_after_flush.remove(&offset);
    }

    pub(crate) fn set_limit(&mut self, limit: CacheLimit) {
        self.limit = limit;
        self.limit_bytes = cache_limit_bytes(limit);
        self.trim_to_limit();
    }

    pub(crate) fn trim_to(&mut self, bytes: u64) {
        self.limit = CacheLimit::Bytes(bytes);
        self.limit_bytes = bytes;
        self.trim_to_limit();
    }

    pub(crate) fn stats(&self) -> CacheStats {
        CacheStats {
            limit_bytes: self.limit_bytes,
            used_bytes: self.used_bytes,
            entries: self.pages.len(),
            hits: self.hits,
            misses: self.misses,
        }
    }

    fn refresh_limit_if_needed(&mut self) {
        if self.limit != CacheLimit::Auto {
            return;
        }
        self.operations_since_resize = self.operations_since_resize.saturating_add(1);
        if self.operations_since_resize < AUTO_RESIZE_INTERVAL {
            return;
        }
        self.operations_since_resize = 0;
        let next_limit = cache_limit_bytes(CacheLimit::Auto);
        if next_limit < self.limit_bytes {
            self.limit_bytes = next_limit;
            self.trim_to_limit();
        } else {
            self.limit_bytes = next_limit;
        }
    }

    fn trim_to_limit(&mut self) {
        while self.used_bytes > self.limit_bytes {
            let Some(offset) = self.recent.pop_front() else {
                break;
            };
            let Some(page) = self.pages.get_mut(&offset) else {
                continue;
            };
            if self.dirty_offsets.contains(&offset) {
                self.recent.push_back(offset);
                break;
            }
            if page.generation > 0 {
                page.generation -= 1;
                self.recent.push_back(offset);
                continue;
            }
            let removed = self.pages.remove(&offset).expect("page existed");
            self.used_bytes = self.used_bytes.saturating_sub(removed.weight);
        }
        if self.pages.is_empty() {
            self.recent.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::DecodedPage;

    #[test]
    fn evicts_by_weight() {
        let mut cache = PageCache::new(CacheLimit::Bytes(1_100));
        cache.insert_page(1, page(1), 500);
        cache.insert_page(2, page(2), 500);
        cache.insert_page(3, page(3), 500);
        assert!(cache.get_page(1).is_none());
        assert!(cache.get_page(2).is_some());
        assert!(cache.get_page(3).is_some());
    }

    #[test]
    fn explicit_trim_reduces_usage() {
        let mut cache = PageCache::new(CacheLimit::Bytes(2_000));
        cache.insert_page(1, page(1), 500);
        cache.insert_page(2, page(2), 500);
        cache.trim_to(400);
        assert!(cache.stats().used_bytes <= 400);
    }

    fn page(page_id: u64) -> DecodedPage {
        DecodedPage {
            page_id,
            sequence: page_id,
            objects: Vec::new(),
        }
    }
}
