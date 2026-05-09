use crate::constants::DEFAULT_MAX_SEGMENT_BODY_BYTES;

const MIB: u64 = 1024 * 1024;
const DEFAULT_NATIVE_MAX_CACHE_BYTES: u64 = 512 * MIB;
const DEFAULT_WASM_CACHE_BYTES: u64 = 64 * MIB;
const DEFAULT_FALLBACK_CACHE_BYTES: u64 = 128 * MIB;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheLimit {
    Auto,
    Bytes(u64),
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockboxOptions {
    pub cache_limit: CacheLimit,
}

impl Default for LockboxOptions {
    fn default() -> Self {
        Self {
            cache_limit: CacheLimit::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub limit_bytes: u64,
    pub used_bytes: u64,
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
}

pub(crate) fn cache_limit_bytes(limit: CacheLimit) -> u64 {
    match limit {
        CacheLimit::Disabled => 0,
        CacheLimit::Bytes(bytes) => bytes,
        CacheLimit::Auto => auto_cache_limit_bytes(),
    }
}

pub(crate) fn auto_cache_limit_bytes() -> u64 {
    if cfg!(target_arch = "wasm32") {
        return DEFAULT_WASM_CACHE_BYTES;
    }

    let min_cache = minimum_useful_cache_bytes();
    let Some(available) = crate::memory_pressure::available_memory_bytes() else {
        return DEFAULT_FALLBACK_CACHE_BYTES.max(min_cache);
    };
    let target = available.saturating_mul(3) / 100;
    target.clamp(min_cache, DEFAULT_NATIVE_MAX_CACHE_BYTES)
}

fn minimum_useful_cache_bytes() -> u64 {
    let by_segment = (DEFAULT_MAX_SEGMENT_BODY_BYTES as u64).saturating_mul(8);
    by_segment.max(64 * MIB)
}
