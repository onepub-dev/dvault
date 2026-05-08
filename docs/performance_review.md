# Performance Review

This pass focuses on the two high-pressure paths: full recursive add and full
vault expansion/extraction.

## Current Strengths

- File content APIs stream through `Read`/`Write` for add and extract.
- Single-file range reads are chunk-aware and avoid materializing the whole
  file for segmented entries.
- The CLI can recursively add a source directory without requiring callers to
  enumerate files themselves.
- Content is segmented at bounded sizes instead of solid-compressing the whole
  vault.
- Records are independently compressed/encrypted, which keeps random access and
  partial recovery practical.
- Listing can stream through `list_iter` rather than materializing every entry.
- Small-file packing reduces pathological overhead for many tiny files.

## Current Bottlenecks

- The vault is still backed by one `Vec<u8>`. Large recursive adds and large
  expansions will eventually need file-backed IO instead of holding the whole
  vault in memory.
- `commit()` encodes the whole manifest as one checkpoint. For very large
  vaults this will dominate commit time and memory. The planned segmented TOC
  should become a real paged/indexed manifest.
- `pack_small_file_segments()` currently calls `get_file()` for candidate files,
  which re-reads/decrypts/decompresses data during commit. That is expensive for
  large recursive adds with many small files.
- Free-slot lookup is linear. Fragmented vaults with many reusable records will
  need size-class bins or an ordered free-space index.
- Full expansion currently walks manifest entries serially. It should support a
  bounded worker pool for independent records.

## Required Next Changes

- Introduce file-backed `LockboxReader`/`LockboxWriter` storage traits so CLI
  operations do not keep the whole vault in memory.
- Replace monolithic manifest checkpoints with segmented/paged TOC records.
- Preserve pending small-file bytes during recursive add so packing does not
  have to re-read from encrypted records.
- Add a free-space index keyed by slot size.
- Add recursive add and full extraction benchmarks with representative mixes:
  many tiny files, medium source trees, large incompressible files, and highly
  compressible files.

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
LOCKBOX_PERF_FILES=100000 \
LOCKBOX_PERF_FILE_BYTES=1024 \
cargo run -p lockbox_core --example perf --release

# A GB-class large file without keeping the source payload in memory.
LOCKBOX_PERF_SCENARIO=large \
LOCKBOX_PERF_LARGE_BYTES=1073741824 \
LOCKBOX_PERF_PATTERN=randomish \
cargo run -p lockbox_core --example perf --release

# Append/delete/replacement workload.
LOCKBOX_PERF_SCENARIO=append-delete \
LOCKBOX_PERF_INITIAL_FILES=50000 \
LOCKBOX_PERF_APPEND_FILES=10000 \
LOCKBOX_PERF_FILE_BYTES=2048 \
cargo run -p lockbox_core --example perf --release

# Run all scenarios with their configured sizes.
LOCKBOX_PERF_SCENARIO=all cargo run -p lockbox_core --example perf --release
```

This is not a replacement for Criterion or production profiling, but it gives a
repeatable smoke signal before storage-format changes. It reports file count,
logical bytes, vault bytes, add time, commit time, list time, extraction or
delete/replace time, large-file range-read latency, and vault/logical size
ratio.

The large-file scenario is intended for GB-class baselines. It uses a streaming
reader so the generated input does not need a separate GB fixture on disk, but
the current vault implementation still holds vault bytes in memory. That is one
of the measurements this baseline is meant to expose before the file-backed
store work starts.
