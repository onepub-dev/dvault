# Performance Review

This pass focuses on the two high-pressure paths: full recursive add and full
lockbox expansion/extraction.

## Current Strengths

- File content APIs stream through `Read`/`Write` for add and extract.
- Single-file range reads are chunk-aware and avoid materializing the whole
  file for pageed entries.
- The CLI can recursively add a source directory without requiring callers to
  enumerate files themselves.
- Content is pageed at bounded sizes instead of solid-compressing the whole
  lockbox.
- Records are independently compressed/encrypted, which keeps random access and
  partial recovery practical.
- Listing can stream through `list_iter` rather than materializing every entry.
- Small-file packing reduces pathological overhead for many tiny files.
- File-backed lockbox storage can read records by byte range and append records
  directly to disk, which avoids materializing the whole lockbox for normal CLI
  access.
- Full extraction caches decoded packed-file records per extraction pass, so a
  packed page is not decrypted/decompressed once per contained file.
- Directory extraction streams file content to disk. When the destination does
  not already exist, extraction is staged into a sibling temporary directory and
  completed with an OS rename/move (`std::fs::rename`) after all files have been
  written.

## Current Bottlenecks

- Structural TOC changes still rebuild the affected leaf directory and parent
  structure. Compatible updates rewrite only the touched leaf and changed
  ancestors, but split/merge-heavy workloads need more profiling.
- Free-slot lookup now uses ordered offset and size indexes in memory. The
  format persists that free-space state through a commit-root-referenced
  free-index page so reopening does not lose reusable regions.
- Commit roots, free-space index checkpoints, TOC nodes, file data, symlinks,
  delete markers, and environment records are now written as fixed-size
  encrypted pages.
- Full expansion currently walks manifest entries serially. It should support a
  bounded worker pool for independent records.
- The convenience extraction APIs still return owned `Vec<u8>` values. That is
  appropriate for language bindings and small extractions, but CLI-scale
  extraction should use `extract_to_directory`, which now streams directly to
  the filesystem.

## Required Next Changes

- Expand Criterion coverage for root height increase/decrease at larger TOC
  sizes.
- Keep the existing quick smoke/perf example for GB-class local profiling and
  use Criterion for repeatable micro/structural benchmarks.

## Benchmark Targets

- Recursive add throughput in MiB/s and files/s.
- Commit time by number of entries.
- Peak RSS during recursive add.
- Full extraction throughput in MiB/s and files/s.
- Single-file range-read latency for large files.
- Manifest open/list latency for 10k, 100k, and 1M entries.

## Current Benchmark Harness

A lightweight benchmark-style example exists at
`rust/lockbox_core/examples/perf.rs`:

```bash
cd rust
cargo run -p lockbox_core --example perf --release
```

Scenarios:

```bash
# Many small files. This is the default.
LOCKBOX_PERF_SCENARIO=small \
LOCKBOX_PERF_BACKEND=memory \
LOCKBOX_PERF_EXTRACT=memory \
LOCKBOX_PERF_EXTRACT_REPEAT=20 \
LOCKBOX_PERF_FILES=100000 \
LOCKBOX_PERF_FILE_BYTES=1024 \
cargo run -p lockbox_core --example perf --release

# A GB-class large file without keeping the source payload in memory.
LOCKBOX_PERF_SCENARIO=large \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_LARGE_BYTES=1073741824 \
LOCKBOX_PERF_PATTERN=randomish \
cargo run -p lockbox_core --example perf --release

# Append/delete/replacement workload.
LOCKBOX_PERF_SCENARIO=append-delete \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_INITIAL_FILES=50000 \
LOCKBOX_PERF_APPEND_FILES=10000 \
LOCKBOX_PERF_FILE_BYTES=2048 \
cargo run -p lockbox_core --example perf --release

# Run all scenarios with their configured sizes.
LOCKBOX_PERF_SCENARIO=all cargo run -p lockbox_core --example perf --release
```

This is not a replacement for Criterion or production profiling, but it gives a
repeatable smoke signal before storage-format changes. It reports file count,
logical bytes, lockbox bytes, add time, commit time, list time, extraction or
delete/replace time, large-file range-read latency, and lockbox/logical size
ratio.

The large-file scenario is intended for GB-class baselines. It uses a streaming
reader so the generated input does not need a separate GB fixture on disk. With
`LOCKBOX_PERF_BACKEND=file`, pages are written to and read from the lockbox file by
range; with `LOCKBOX_PERF_BACKEND=memory`, the lockbox bytes are intentionally
kept in memory for comparison.

`LOCKBOX_PERF_BACKEND` accepts:

- `memory`: the historical in-memory store.
- `file`: the file-backed store that reads pages by range and writes pages
  directly to a lockbox file.

## Current Baseline Observations

Detailed benchmark run history is kept in
[Benchmark History](benchmark_history.md). Append a dated entry there whenever
benchmarks are run for a meaningful implementation or format change.

Small-file overhead was the dominant problem in the first benchmark pass. The
current write path stages small files and writes them into packed file-page
pages during commit, instead of writing one padded page per file and
repacking later.

Representative current results from the latest local pass:

- 10,000 x 1 KiB files, file backend, directory extract: add ~24ms, commit
  ~47ms, list ~0.6ms, extract ~195ms, lockbox/logical ratio ~0.019.
- 50,000 x 1 KiB files, file backend, 20 repeated memory extraction passes:
  add ~128ms, commit ~196ms, list ~6ms, extract ~1.37s, lockbox/logical ratio
  ~0.014.
- Append/delete workload with 5,000 initial files, 1,000 appended files, 1,000
  deletes, and 1,000 replacements: commit ~12ms, lockbox/logical ratio ~0.032.
- 100,000 x 1 KiB files, file backend, 5 repeated memory extraction passes:
  add ~202ms, commit ~294ms, list ~9ms, extract ~546ms, lockbox/logical ratio
  ~0.014.
- 256 MiB low-compressibility file, file backend: add ~1.95s, commit <1ms,
  full memory extract ~666ms, 1 MiB range read ~23ms, lockbox/logical ratio
  ~1.000.
- Larger append/delete workload with 50,000 initial files, 10,000 appended
  files, 10,000 deletes, and 10,000 replacements: commit ~117ms, list ~7ms,
  lockbox/logical ratio ~0.015.

Deletes are also staged and written as batched delete pages during commit.
Without this, delete-heavy workloads paid one padded page per deleted path.

`perf` and `cargo flamegraph` are available in the local environment. Kernel
symbols remain restricted, but user-space Rust symbols resolve well enough for
hotspot work.

The focused small-file flamegraph uses:

```bash
CARGO_PROFILE_RELEASE_DEBUG=true \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_SCENARIO=small \
LOCKBOX_PERF_EXTRACT=memory \
LOCKBOX_PERF_EXTRACT_REPEAT=20 \
LOCKBOX_PERF_FILES=50000 \
LOCKBOX_PERF_FILE_BYTES=1024 \
cargo flamegraph -p lockbox_core --example perf --release \
  -o target/flamegraph-small-memory-debug-hash-cache.svg
```

Current small-file extraction profile:

- In-memory extraction: ~35ms.
- Directory extraction: ~285ms without tracing after streaming to a sibling
  temporary directory and completing with `std::fs::rename`; ~1.87s under
  `strace`.
- `strace -c` syscall time was dominated by `openat`, `unlinkat`, `write`,
  `mkdir`, `statx`, and `close`, with about 60k syscalls for 10k extracted
  files.
- 50,000 x 1 KiB files with 20 repeated in-memory extraction passes:
  previously ~4.35s, then ~3.35s after ASCII path validation fast paths, then
  ~1.5s after flattening the packed-page extraction cache, and now roughly
  ~1.37s after using the TOC-validated fast iterator for extraction.
- The current user-space flamegraph is dominated by allocation/copying,
  `decode_file_page_payload`, default `HashMap` hashing, ASCII path
  validation, and Zstd decompression. Page crypto is not currently a top
  small-file extraction hotspot.

The remaining extraction hotspot is therefore not page crypto; it is per-file
allocation/copying for memory extraction and filesystem output for directory
extraction. The next useful optimization is reducing per-file filesystem calls
and testing bounded parallel writes for large directory expansions.

On a 1 GiB low-compressibility file-backed run, the lockbox/logical ratio was
about 1.000, add time was about 10.3s, full extraction was about 3.8s, and a
1 MiB range read from the middle of the file was about 21ms. That validates the
range-read path for large files, while still leaving room for direct IO and
larger read buffers later.
