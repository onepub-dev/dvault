use crate::constants::DEFAULT_METADATA_PAGE_BYTES;

const MIB: u64 = 1024 * 1024;
const DEFAULT_NATIVE_MAX_CACHE_BYTES: u64 = 4 * 1024 * MIB;
const DEFAULT_WASM_CACHE_BYTES: u64 = 64 * MIB;
const DEFAULT_FALLBACK_CACHE_BYTES: u64 = 128 * MIB;
const DEFAULT_NATIVE_AVAILABLE_MEMORY_PERCENT: u64 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Decoded-page cache size policy.
pub enum CacheLimit {
    /// Choose a cache size from the current platform and available memory.
    Auto,
    /// Use an explicit maximum number of decoded page bytes.
    Bytes(u64),
    /// Disable decoded-page caching.
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Options used when creating or opening a lockbox.
pub struct LockboxOptions {
    /// Maximum decoded-page cache size.
    pub cache_limit: CacheLimit,
    /// Expected access pattern used to tune staging and cache behavior.
    pub workload_profile: WorkloadProfile,
}

impl Default for LockboxOptions {
    fn default() -> Self {
        Self {
            cache_limit: CacheLimit::Auto,
            workload_profile: WorkloadProfile::Interactive,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// High-level access pattern hint for cache and write behavior.
pub enum WorkloadProfile {
    /// Balanced defaults for interactive CLI/API use.
    Interactive,
    /// Prefer bounded memory during large imports.
    BulkImport,
    /// Favor repeated reads from an existing lockbox.
    ReadMostly,
    /// Favor extracting many records in sequence.
    ExtractMany,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Snapshot of decoded-page cache usage.
pub struct CacheStats {
    /// Current cache limit in bytes.
    pub limit_bytes: u64,
    /// Approximate bytes currently held by decoded pages.
    pub used_bytes: u64,
    /// Number of decoded page entries.
    pub entries: usize,
    /// Cache hit count since the current cache was created.
    pub hits: u64,
    /// Cache miss count since the current cache was created.
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
    let target = available.saturating_mul(DEFAULT_NATIVE_AVAILABLE_MEMORY_PERCENT) / 100;
    target.clamp(min_cache, DEFAULT_NATIVE_MAX_CACHE_BYTES)
}

fn minimum_useful_cache_bytes() -> u64 {
    let by_page = (DEFAULT_METADATA_PAGE_BYTES as u64).saturating_mul(64);
    by_page.max(64 * MIB)
}
