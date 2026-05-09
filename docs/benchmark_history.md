# Benchmark History

This file records benchmark runs that are useful for comparing format,
dependency, or implementation changes. Keep each entry self-contained: include
the change being measured, the command, environment, baseline source, and
observed result table.

## 2026-05-09 - Pure-Rust zstd Backend

Description: switched `lockbox_core` compression from the native `zstd` C
backend to pure-Rust `oxiarc-zstd` so desktop, mobile, and WASM builds avoid a
C zstd dependency. The first run exposed a fixed-page accounting bug in the
large-file benchmark; the page size stayed 8 MiB, and max object payload was
reduced by 4 KiB to reserve space for page/object/compression/AEAD framing.

Command:

```bash
cd rust
cargo bench -p lockbox_core --bench performance
```

Environment:

- Host: `Linux slayer4 6.11.0-26-generic x86_64`
- CPU: `AMD Ryzen 7 3700X 8-Core Processor`, 8 cores / 16 threads
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Commit: recorded by the git revision that adds this entry; the comparison
  base before the page-sizing fix was `97ecbd8`
- Benchmark harness: Criterion, sample size 10 per benchmark
- Baseline source: local Criterion `target/criterion/*/new/estimates.json`
  saved before the pure-Rust zstd benchmark run

Results:

| Benchmark | Previous mean | New mean | Change |
| --- | ---: | ---: | ---: |
| `small_files/add_commit_1000x1k` | 3.005 ms | 34.340 ms | +1042.9% |
| `small_files/extract_memory_1000x1k` | 0.880 ms | 0.291 ms | -66.9% |
| `small_files/extract_directory_1000x1k` | 28.650 ms | 23.489 ms | -18.0% |
| `mixed_tree/add_commit_mixed` | 11.746 ms | 81.185 ms | +591.2% |
| `mixed_tree/list_recursive_mixed` | 0.0107 ms | 0.0090 ms | -16.0% |
| `mixed_tree/extract_directory_mixed` | 10.956 ms | 10.885 ms | -0.7% |
| `large_file/add_commit_16m_randomish` | 158.460 ms | 846.612 ms | +434.3% |
| `large_file/range_read_1m_middle` | 19.719 ms | 2.369 ms | -88.0% |
| `append_delete/append_delete_replace_commit` | 2.777 ms | 85.320 ms | +2972.4% |

Additional new TOC-structure benchmark results did not have a saved local
baseline:

| Benchmark | New mean |
| --- | ---: |
| `toc_structure/separator_update_5000` | 90.258 ms |
| `toc_structure/leaf_split_append_5000` | 77.648 ms |
| `toc_structure/leaf_merge_delete_5000` | 73.523 ms |

Conclusion:

- Pure-Rust zstd removes the C dependency successfully, but write-heavy paths
  are substantially slower because compression dominates segment creation.
- Read/extract/list paths are flat to materially faster in this run, especially
  the large-file range read.
- The next performance step should profile compression during commit and decide
  whether to tune `oxiarc-zstd`, skip compression for incompressible/high-entropy
  file segments earlier, or make compression level/strategy configurable while
  still defaulting to a C-free backend.

## 2026-05-09 - High-Entropy Compression Skip

Description: profiled the large low-compressibility write path with
`cargo flamegraph`; the resolved samples were dominated by
`oxiarc_zstd::lz77::MatchFinder`. Added a segment-body precheck that samples
large payloads and stores high-entropy bodies uncompressed instead of first
running zstd and then discarding the larger result.

Command:

```bash
cd rust
cargo bench -p lockbox_core --bench performance
```

Environment:

- Host: `Linux slayer4 6.11.0-26-generic x86_64`
- CPU: `AMD Ryzen 7 3700X 8-Core Processor`, 8 cores / 16 threads
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Benchmark harness: Criterion, sample size 10 per benchmark
- Baseline source: local Criterion `target/criterion/*/new/estimates.json`
  saved after the pure-Rust zstd run and before this optimization
- Profile artifact: `rust/target/flamegraph-large-randomish-zstd.svg`

Results:

| Benchmark | Previous mean | New mean | Change |
| --- | ---: | ---: | ---: |
| `small_files/add_commit_1000x1k` | 34.340 ms | 34.980 ms | +1.9% |
| `small_files/extract_memory_1000x1k` | 0.291 ms | 0.329 ms | +12.8% |
| `small_files/extract_directory_1000x1k` | 23.489 ms | 26.253 ms | +11.8% |
| `mixed_tree/add_commit_mixed` | 81.185 ms | 89.475 ms | +10.2% |
| `mixed_tree/list_recursive_mixed` | 0.0090 ms | 0.0095 ms | +6.0% |
| `mixed_tree/extract_directory_mixed` | 10.885 ms | 10.413 ms | -4.3% |
| `large_file/add_commit_16m_randomish` | 846.612 ms | 203.331 ms | -76.0% |
| `large_file/range_read_1m_middle` | 2.369 ms | 2.729 ms | +15.2% |
| `append_delete/append_delete_replace_commit` | 85.320 ms | 78.142 ms | -8.4% |
| `toc_structure/separator_update_5000` | 89.577 ms | 72.536 ms | -19.0% |
| `toc_structure/leaf_split_append_5000` | 77.450 ms | 83.060 ms | +7.2% |
| `toc_structure/leaf_merge_delete_5000` | 72.636 ms | 79.650 ms | +9.7% |

Conclusion:

- The entropy skip is a material win for incompressible large-file ingestion and
  avoids the worst pure-Rust zstd regression while keeping the C-free backend.
- Compressible small-file packing remains intentionally unchanged; those segment
  bodies still compress well.
- Several small read/extract results moved backward in this run. Those paths do
  not execute the new entropy check while reading, so treat them as a signal for
  follow-up profiling rather than proof of causation.
- The next step is to profile the post-optimization large write path and the
  mixed-tree commit path to identify the remaining dominant cost.

## 2026-05-09 - Deterministic File-Segment Offsets

Description: after the entropy skip, the large low-compressibility profile
shifted from zstd to file writes, page encoding, stream generation, and segment
crypto. Removed a write-side round trip where file segment pages were read back
through storage/decrypt/decode immediately after writing only to recover
`segment_inner_offset` values. Those offsets are deterministic from the file
segment payload layout, so they are now computed before writing.

Command:

```bash
cd rust
cargo bench -p lockbox_core --bench performance
```

Environment:

- Host: `Linux slayer4 6.11.0-26-generic x86_64`
- CPU: `AMD Ryzen 7 3700X 8-Core Processor`, 8 cores / 16 threads
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Benchmark harness: Criterion, sample size 10 per benchmark
- Baseline source: local Criterion `target/criterion/*/new/estimates.json`
  saved after the high-entropy compression skip run
- Profile artifact: `rust/target/flamegraph-large-randomish-entropy-skip.svg`

Results:

| Benchmark | Previous mean | New mean | Change |
| --- | ---: | ---: | ---: |
| `small_files/add_commit_1000x1k` | 34.980 ms | 37.217 ms | +6.4% |
| `small_files/extract_memory_1000x1k` | 0.329 ms | 0.384 ms | +16.9% |
| `small_files/extract_directory_1000x1k` | 26.253 ms | 28.656 ms | +9.2% |
| `mixed_tree/add_commit_mixed` | 89.475 ms | 62.288 ms | -30.4% |
| `mixed_tree/list_recursive_mixed` | 0.0095 ms | 0.0111 ms | +17.5% |
| `mixed_tree/extract_directory_mixed` | 10.413 ms | 11.052 ms | +6.1% |
| `large_file/add_commit_16m_randomish` | 203.331 ms | 175.606 ms | -13.6% |
| `large_file/range_read_1m_middle` | 2.729 ms | 2.593 ms | -5.0% |
| `append_delete/append_delete_replace_commit` | 78.142 ms | 82.245 ms | +5.2% |
| `toc_structure/separator_update_5000` | 72.536 ms | 75.073 ms | +3.5% |
| `toc_structure/leaf_split_append_5000` | 83.060 ms | 80.108 ms | -3.6% |
| `toc_structure/leaf_merge_delete_5000` | 79.650 ms | 74.567 ms | -6.4% |

Conclusion:

- Removing the immediate read/decode round trip materially improves large-file
  and mixed-tree ingestion.
- Some small-file and read-only benches regressed. The change removed an
  incidental cache-warming side effect during writes, so follow-up profiling
  should separate cold-cache and warm-cache extraction/list measurements before
  adding any write-through cache behavior.
- The next useful write-side optimization is likely reducing page assembly
  copies or improving file-backed storage writes; zstd is no longer the main
  low-compressibility write bottleneck.

## 2026-05-09 - Explicit Write-Through Segment Cache

Description: the deterministic-offset change removed an accidental readback
that had been warming the segment cache. Added explicit cache insertion for
newly written decoded segment pages. This keeps writes going through the segment
cache intentionally, without rereading encrypted bytes from storage.

Command:

```bash
cd rust
cargo bench -p lockbox_core --bench performance
```

Environment:

- Host: `Linux slayer4 6.11.0-26-generic x86_64`
- CPU: `AMD Ryzen 7 3700X 8-Core Processor`, 8 cores / 16 threads
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Benchmark harness: Criterion, sample size 10 per benchmark
- Baseline source: local Criterion `target/criterion/*/new/estimates.json`
  saved after deterministic file-segment offsets and before write-through cache

Results:

| Benchmark | Previous mean | New mean | Change |
| --- | ---: | ---: | ---: |
| `small_files/add_commit_1000x1k` | 37.217 ms | 29.170 ms | -21.6% |
| `small_files/extract_memory_1000x1k` | 0.384 ms | 0.303 ms | -21.2% |
| `small_files/extract_directory_1000x1k` | 28.656 ms | 23.441 ms | -18.2% |
| `mixed_tree/add_commit_mixed` | 62.288 ms | 66.803 ms | +7.2% |
| `mixed_tree/list_recursive_mixed` | 0.0111 ms | 0.0084 ms | -25.1% |
| `mixed_tree/extract_directory_mixed` | 11.052 ms | 8.967 ms | -18.9% |
| `large_file/add_commit_16m_randomish` | 175.606 ms | 113.344 ms | -35.5% |
| `large_file/range_read_1m_middle` | 2.593 ms | 1.827 ms | -29.5% |
| `append_delete/append_delete_replace_commit` | 82.245 ms | 65.059 ms | -20.9% |
| `toc_structure/separator_update_5000` | 75.073 ms | 59.269 ms | -21.1% |
| `toc_structure/leaf_split_append_5000` | 80.108 ms | 61.706 ms | -23.0% |
| `toc_structure/leaf_merge_delete_5000` | 74.567 ms | 59.288 ms | -20.5% |

Conclusion:

- Explicit write-through caching recovers the warm-cache behavior without the
  old storage/decrypt/decode round trip.
- Nearly every benchmark improves materially in this pass; the only regression
  is `mixed_tree/add_commit_mixed`, which remains faster than the pre-offset
  baseline.
- The next profiling pass should look at page assembly, storage writes, and
  remaining compression in mixed compressible workloads.

## 2026-05-09 - Zstd Level 1 Default

Description: the current small-file write profile still showed pure-Rust zstd
as a visible cost for highly compressible packed pages. Changed the default
segment compression level from zstd level 3 to level 1 and benchmarked the
effect. This keeps zstd compression enabled by default; it only changes the
speed/ratio point.

Command:

```bash
cd rust
cargo bench -p lockbox_core --bench performance
```

Environment:

- Host: `Linux slayer4 6.11.0-26-generic x86_64`
- CPU: `AMD Ryzen 7 3700X 8-Core Processor`, 8 cores / 16 threads
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Benchmark harness: Criterion, sample size 10 per benchmark
- Baseline source: local Criterion `target/criterion/*/new/estimates.json`
  saved after explicit write-through segment caching
- Profile artifact: `rust/target/flamegraph-small-write-cache.svg`

Results:

| Benchmark | Previous mean | New mean | Change |
| --- | ---: | ---: | ---: |
| `small_files/add_commit_1000x1k` | 29.170 ms | 27.902 ms | -4.3% |
| `small_files/extract_memory_1000x1k` | 0.303 ms | 0.299 ms | -1.2% |
| `small_files/extract_directory_1000x1k` | 23.441 ms | 23.203 ms | -1.0% |
| `mixed_tree/add_commit_mixed` | 66.803 ms | 63.150 ms | -5.5% |
| `mixed_tree/list_recursive_mixed` | 0.0084 ms | 0.0072 ms | -13.3% |
| `mixed_tree/extract_directory_mixed` | 8.967 ms | 8.987 ms | +0.2% |
| `large_file/add_commit_16m_randomish` | 113.344 ms | 112.213 ms | -1.0% |
| `large_file/range_read_1m_middle` | 1.827 ms | 1.559 ms | -14.7% |
| `append_delete/append_delete_replace_commit` | 65.059 ms | 61.914 ms | -4.8% |
| `toc_structure/separator_update_5000` | 59.269 ms | 67.447 ms | +13.8% |
| `toc_structure/leaf_split_append_5000` | 61.706 ms | 56.694 ms | -8.1% |
| `toc_structure/leaf_merge_delete_5000` | 59.288 ms | 54.955 ms | -7.3% |

Conclusion:

- Level 1 is a net win across the current benchmark set, especially for
  write-heavy paths that still compress segment bodies.
- `toc_structure/separator_update_5000` regressed in this run, so future TOC
  profiling should verify whether that is noise, cache state, or a real
  compression-level interaction.
- Keep level 1 as the default unless production-size vault benchmarks show a
  meaningful space regression.

## 2026-05-09 - Production-Scale File-Backed Compression Check

Description: ran the file-backed performance example against production-sized
inputs after profiling. The initial 1 GiB check showed that compression was not
reducing vault size for large files because chunks were sized by uncompressed
payload and every physical segment page is fixed at 8 MiB. Added a stronger
test that compares fixed-page usage for compressible and high-entropy large
files, then changed large-file chunking so a compressed segment page can
represent up to 64 MiB of logical file data. High-entropy data and known
already-compressed extensions still use normal page-sized chunks.

Commands:

```bash
cd rust
LOCKBOX_PERF_SCENARIO=large \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_LARGE_BYTES=1073741824 \
LOCKBOX_PERF_PATTERN=zero \
LOCKBOX_PERF_EXTRACT=memory \
cargo run -p lockbox_core --example perf --release

LOCKBOX_PERF_SCENARIO=large \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_LARGE_BYTES=1073741824 \
LOCKBOX_PERF_PATTERN=randomish \
LOCKBOX_PERF_EXTRACT=memory \
cargo run -p lockbox_core --example perf --release

LOCKBOX_PERF_SCENARIO=small \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_FILES=100000 \
LOCKBOX_PERF_FILE_BYTES=1024 \
LOCKBOX_PERF_EXTRACT=memory \
LOCKBOX_PERF_EXTRACT_REPEAT=5 \
cargo run -p lockbox_core --example perf --release

LOCKBOX_PERF_SCENARIO=append-delete \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_INITIAL_FILES=50000 \
LOCKBOX_PERF_APPEND_FILES=10000 \
LOCKBOX_PERF_FILE_BYTES=2048 \
cargo run -p lockbox_core --example perf --release
```

Environment:

- Host: `Linux slayer4 6.11.0-26-generic x86_64`
- CPU: `AMD Ryzen 7 3700X 8-Core Processor`, 8 cores / 16 threads
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Backend: file-backed vault storage
- Profile artifact: `rust/target/flamegraph-file-small-50k.svg`

Results after compressed logical chunking:

| Scenario | Logical bytes | Vault bytes | Add | Commit | Extract/Delete | Range read | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 GiB zero large file | 1,073,741,824 | 159,383,616 | 2.770s | 15.158ms | 2.454s | 112.452ms | 0.148 |
| 1 GiB randomish large file | 1,073,741,824 | 1,098,907,712 | 6.412s | 17.466ms | 1.787s | 6.749ms | 1.023 |
| 100k x 1 KiB files, 5 memory extracts | 102,400,000 | 142,606,400 | 205.323ms | 1.299s | 612.156ms | n/a | 1.393 |
| 50k initial + 10k append/delete/replace | 122,880,000 | 184,549,440 | 21.900ms | 516.788ms | 25.625ms | n/a | 1.502 |

Conclusion:

- The old large-file behavior failed a meaningful compression standard:
  1 GiB zero and 1 GiB randomish files both used the same vault size.
- The new behavior gives real page-count savings for compressible large files,
  but the fixed 8 MiB physical page design creates a compression floor. With
  the current 64 MiB logical cap, the best possible ratio for a huge perfectly
  compressible file is about 12.5% before metadata.
- The measured 14.8% ratio is close to that fixed-page floor, but it is not
  competitive with conventional zstd archives for highly compressible data.
- Range reads from very compressible large files are slower because one fixed
  page can now decode to 64 MiB of logical data.
- A true best-compression design needs variable physical compressed extents or
  a higher-level compressed-extent mode; tuning zstd alone cannot overcome the
  fixed-page floor.

Criterion comparison after the compressed logical chunking change:

| Benchmark | Previous mean | New mean | Change |
| --- | ---: | ---: | ---: |
| `small_files/add_commit_1000x1k` | 27.902 ms | 27.676 ms | -0.8% |
| `small_files/extract_memory_1000x1k` | 0.299 ms | 0.297 ms | -0.8% |
| `small_files/extract_directory_1000x1k` | 23.203 ms | 23.132 ms | -0.3% |
| `mixed_tree/add_commit_mixed` | 63.150 ms | 62.639 ms | -0.8% |
| `mixed_tree/list_recursive_mixed` | 0.0072 ms | 0.0073 ms | +0.4% |
| `mixed_tree/extract_directory_mixed` | 8.987 ms | 8.875 ms | -1.2% |
| `large_file/add_commit_16m_randomish` | 112.213 ms | 118.024 ms | +5.2% |
| `large_file/range_read_1m_middle` | 1.559 ms | 1.787 ms | +14.6% |
| `append_delete/append_delete_replace_commit` | 61.914 ms | 64.028 ms | +3.4% |
| `toc_structure/separator_update_5000` | 67.447 ms | 56.630 ms | -16.0% |
| `toc_structure/leaf_split_append_5000` | 56.694 ms | 58.248 ms | +2.7% |
| `toc_structure/leaf_merge_delete_5000` | 54.955 ms | 56.379 ms | +2.6% |

The earlier TOC separator regression did not reproduce in this run. The
remaining large-file regressions are the expected cost of testing and adapting
larger logical chunks before falling back for high-entropy data.
