use crate::constants::DEFAULT_METADATA_PAGE_BYTES;

const MIB: u64 = 1024 * 1024;
const DEFAULT_NATIVE_MAX_CACHE_BYTES: u64 = 4 * 1024 * MIB;
const DEFAULT_WASM_CACHE_BYTES: u64 = 64 * MIB;
const DEFAULT_FALLBACK_CACHE_BYTES: u64 = 128 * MIB;
const DEFAULT_NATIVE_AVAILABLE_MEMORY_PERCENT: u64 = 15;
const DEFAULT_NATIVE_AUTO_WORKERS: usize = 6;

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
    /// Worker policy for native page/frame preparation.
    pub worker_policy: WorkerPolicy,
}

impl Default for LockboxOptions {
    fn default() -> Self {
        Self {
            cache_limit: CacheLimit::Auto,
            workload_profile: WorkloadProfile::Interactive,
            worker_policy: WorkerPolicy::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Worker policy for CPU-heavy lockbox work.
///
/// Browser-style WASM builds should treat `Auto` as single-threaded unless the
/// embedding explicitly provides a threaded worker implementation. Native
/// callers can use `Threads` to bound CPU and memory use, or `Single` for
/// deterministic low-overhead operation.
pub enum WorkerPolicy {
    /// Use the platform default. Native builds use available parallelism capped
    /// at a conservative default; browser/WASM builds use one worker.
    Auto,
    /// Disable worker threads.
    Single,
    /// Use at most this many workers. A value below one is normalized to one.
    Threads(usize),
}

impl WorkerPolicy {
    pub(crate) fn effective_jobs(self) -> usize {
        match self {
            Self::Single => 1,
            Self::Threads(jobs) => jobs.max(1),
            Self::Auto => {
                if cfg!(target_arch = "wasm32") {
                    1
                } else {
                    std::thread::available_parallelism()
                        .map(usize::from)
                        .unwrap_or(1)
                        .min(DEFAULT_NATIVE_AUTO_WORKERS)
                        .max(1)
                }
            }
        }
    }
}

/// High-level access pattern hint for cache and write behavior.
///
/// This value is a tuning hint, not a security setting. It does not change the
/// lockbox file format or the data returned by any API. The current
/// implementation uses the profile to decide how aggressively to retain staged
/// file pages during writes, which compression-frame target and zstd level to
/// use for bulk imports, and whether decoded compression frames may be retained
/// during repeated read/extract workloads; decoded-page cache capacity is still
/// controlled by `LockboxOptions::cache_limit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadProfile {
    /// Balanced defaults for interactive CLI/API use.
    ///
    /// Use this for normal applications that mix reads, writes, listing, and
    /// occasional commits. Small files may be kept in staging memory and packed
    /// together before commit so repeated edits can be compact and efficient.
    /// This is the default profile.
    Interactive,
    /// Prefer bounded memory during large imports.
    ///
    /// Use this when adding many files or very large batches where predictable
    /// memory use matters more than post-import packing. Small-file staging is
    /// flushed incrementally into larger compression frames and file pages
    /// written during import are discarded from the decoded-page cache after
    /// they are flushed. Pending staged data may also be flushed before delete,
    /// rename, or symlink operations that touch the same path. This reduces peak
    /// memory while still allowing archive-style imports to gain compression
    /// from adjacent small files. Compression frames use a stronger zstd level
    /// than interactive writes.
    BulkImport,
    /// Favor repeated reads from an existing lockbox.
    ///
    /// Use this when the lockbox is mostly opened for listing, stat, range
    /// reads, or repeated file extraction with few mutations. Decoded
    /// compression frames may be cached in memory so multiple slices from the
    /// same frame do not require repeated reassembly, digest verification, and
    /// decompression.
    ReadMostly,
    /// Favor extracting many records in sequence.
    ///
    /// Use this when streaming many files out of a lockbox, such as bulk
    /// restore or export flows. Decoded compression frames may be cached in
    /// memory for the duration of the handle, bounded by an internal limit, so
    /// adjacent files packed into the same frame can be extracted without
    /// repeated decompression.
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
