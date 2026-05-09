use crate::cache_options::{cache_limit_bytes, CacheLimit, CacheStats};
use crate::fast_hash::FastBuildHasher;
use crate::lockbox_id::LockboxId;
use crate::segment_page::{
    decode_segment_page, encode_segment_page, DecodedSegmentPage, SegmentObject,
};
use crate::storage::Storage;
use crate::Result;
use std::collections::{HashMap, VecDeque};

const AUTO_RESIZE_INTERVAL: u64 = 256;

#[derive(Debug, Clone)]
pub(crate) struct SegmentManager {
    limit: CacheLimit,
    limit_bytes: u64,
    used_bytes: u64,
    pages: HashMap<u64, CachedPage, FastBuildHasher>,
    recent: VecDeque<u64>,
    hits: u64,
    misses: u64,
    operations_since_resize: u64,
}

#[derive(Debug, Clone)]
struct CachedPage {
    page: DecodedSegmentPage,
    object_positions: HashMap<u64, usize, FastBuildHasher>,
    weight: u64,
    generation: u64,
}

impl SegmentManager {
    pub(crate) fn new(limit: CacheLimit) -> Self {
        Self {
            limit,
            limit_bytes: cache_limit_bytes(limit),
            used_bytes: 0,
            pages: HashMap::with_hasher(FastBuildHasher::default()),
            recent: VecDeque::new(),
            hits: 0,
            misses: 0,
            operations_since_resize: 0,
        }
    }

    pub(crate) fn read_segment_page(
        &mut self,
        storage: &impl Storage,
        offset: u64,
        page_size: usize,
        lockbox_id: LockboxId,
        key: &[u8],
    ) -> Result<DecodedSegmentPage> {
        if let Some(page) = self.get_page(offset) {
            return Ok(page);
        }
        let bytes = storage.read_at(offset, page_size)?;
        let page = decode_segment_page(&bytes, lockbox_id, key)?;
        self.insert_page(offset, page.clone(), page_size as u64);
        Ok(page)
    }

    pub(crate) fn read_segment_object(
        &mut self,
        storage: &impl Storage,
        offset: u64,
        object_id: u64,
        page_size: usize,
        lockbox_id: LockboxId,
        key: &[u8],
    ) -> Result<SegmentObject> {
        if let Some(object) = self.get_page_object(offset, object_id) {
            return Ok(object);
        }
        let bytes = storage.read_at(offset, page_size)?;
        let page = decode_segment_page(&bytes, lockbox_id, key)?;
        let object = page
            .objects
            .iter()
            .find(|object| object.id == object_id)
            .cloned()
            .ok_or(crate::Error::CorruptRecord)?;
        self.insert_page(offset, page, page_size as u64);
        Ok(object)
    }

    pub(crate) fn write_decoded_segment_page(
        &mut self,
        storage: &mut impl Storage,
        offset: u64,
        page_size: usize,
        lockbox_id: LockboxId,
        key: &[u8],
        page: DecodedSegmentPage,
    ) -> Result<()> {
        let encoded = encode_segment_page(
            page_size,
            lockbox_id,
            page.page_id,
            page.sequence,
            key,
            &page.objects,
        )?;
        if offset == storage.len()? {
            let appended = storage.append(&encoded)?;
            if appended != offset {
                return Err(crate::Error::CorruptRecord);
            }
        } else {
            storage.write_at(offset, &encoded)?;
        }
        self.insert_page(offset, page, page_size as u64);
        Ok(())
    }

    pub(crate) fn get_page(&mut self, offset: u64) -> Option<DecodedSegmentPage> {
        self.refresh_limit_if_needed();
        let Some(entry) = self.pages.get_mut(&offset) else {
            self.misses = self.misses.saturating_add(1);
            return None;
        };
        self.hits = self.hits.saturating_add(1);
        entry.generation = entry.generation.saturating_add(1);
        self.recent.push_back(offset);
        Some(entry.page.clone())
    }

    pub(crate) fn get_page_object(&mut self, offset: u64, object_id: u64) -> Option<SegmentObject> {
        self.refresh_limit_if_needed();
        let Some(entry) = self.pages.get_mut(&offset) else {
            self.misses = self.misses.saturating_add(1);
            return None;
        };
        self.hits = self.hits.saturating_add(1);
        entry.generation = entry.generation.saturating_add(1);
        self.recent.push_back(offset);
        let index = *entry.object_positions.get(&object_id)?;
        entry.page.objects.get(index).cloned()
    }

    pub(crate) fn insert_page(&mut self, offset: u64, page: DecodedSegmentPage, weight: u64) {
        self.refresh_limit_if_needed();
        if self.limit_bytes == 0 || weight > self.limit_bytes {
            return;
        }
        if let Some(old) = self.pages.remove(&offset) {
            self.used_bytes = self.used_bytes.saturating_sub(old.weight);
        }
        self.used_bytes = self.used_bytes.saturating_add(weight);
        let object_positions = page
            .objects
            .iter()
            .enumerate()
            .map(|(index, object)| (object.id, index))
            .collect::<HashMap<_, _, FastBuildHasher>>();
        self.pages.insert(
            offset,
            CachedPage {
                page,
                object_positions,
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
        self.recent.clear();
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
    use crate::segment_page::DecodedSegmentPage;

    #[test]
    fn evicts_by_weight() {
        let mut cache = SegmentManager::new(CacheLimit::Bytes(1_100));
        cache.insert_page(1, page(1), 500);
        cache.insert_page(2, page(2), 500);
        cache.insert_page(3, page(3), 500);
        assert!(cache.get_page(1).is_none());
        assert!(cache.get_page(2).is_some());
        assert!(cache.get_page(3).is_some());
    }

    #[test]
    fn explicit_trim_reduces_usage() {
        let mut cache = SegmentManager::new(CacheLimit::Bytes(2_000));
        cache.insert_page(1, page(1), 500);
        cache.insert_page(2, page(2), 500);
        cache.trim_to(400);
        assert!(cache.stats().used_bytes <= 400);
    }

    fn page(page_id: u64) -> DecodedSegmentPage {
        DecodedSegmentPage {
            page_id,
            sequence: page_id,
            objects: Vec::new(),
        }
    }
}
