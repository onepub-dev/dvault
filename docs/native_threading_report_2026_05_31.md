# Native Threading Report - 2026-05-31

## Summary

Implemented native worker support for `lockbox add` through:

- `lockbox --jobs auto|1|N add ...`
- `WorkerPolicy::Auto`, `WorkerPolicy::Single`, and
  `WorkerPolicy::Threads(N)` in `lockbox_core`
- threaded preparation of large-file compression frames
- threaded preparation of bulk small-file compression-frame batches
- ordered page writing and commit publication

The file format is unchanged. Worker threads only prepare independent
compression frames. The writer still owns page/object ids, page writes, TOC
updates, and the final commit root.

## Validation

```text
cargo fmt --manifest-path rust/Cargo.toml --all --check
PASS

cargo test --workspace --manifest-path rust/Cargo.toml
PASS
```

Additional focused coverage added:

```text
threaded_large_file_import_round_trips_multiframe_data
threaded_bulk_small_file_batches_round_trip_after_reopen
worker_policy_single_and_threads_have_same_logical_results
add_accepts_jobs_option_for_large_files
```

The prior TOC spill test failure under local `../zstd-rs/ruzstd` was fixed by
making the test metadata less compressible, so it now reliably exercises a TOC
leaf larger than the minimum physical page.

## Benchmark Setup

Host reports 16 cores via `nproc`.

Command shape:

```bash
cargo build --release -p lockbox_cli --manifest-path rust/Cargo.toml
lockbox --key <bench-key> --jobs <N> add <fresh-lockbox> <fixture> /
```

Raw results:

```text
rust/target/jobs-sweep-20260531/summary.tsv
```

Fixtures reused from:

```text
rust/target/archive-comparison-profile-20260531/fixtures
```

## Best Results

```text
fixture         jobs_1_wall  best_jobs  best_wall  speedup  jobs_1_rss  best_rss
repeated-small       0.46s         15      0.19s    2.42x     20,552     37,956
text-tree            0.35s          7      0.13s    2.69x     21,776     42,104
mixed-tree           0.24s          7      0.21s    1.14x     78,636     93,504
high-entropy         0.69s         12      0.62s    1.11x     78,688     94,200
dvault-source        0.04s          1      0.04s    1.00x     11,404     11,404
```

Output bytes were identical for every job count on every fixture.

## Observations

Threading is a strong wall-time win for compressible many-file imports:

```text
fixture         useful range       note
repeated-small  4-16 jobs          big win; best observed at 15-16
text-tree       4-16 jobs          big win; best observed at 7
mixed-tree      2-16 jobs          small win; high-entropy content dominates
high-entropy    noisy             little benefit; compression mostly skipped/cheap
dvault-source   no real benefit    fixture is too small for worker overhead
```

RSS increases when workers are enabled because multiple compression frames can
be staged at once. The increase was modest for compressible fixtures and about
15 MiB on the high-entropy/mixed fixtures.

## Recommendation

Keep `--jobs auto` as the native default because it materially improves the
archive-style cases users are most likely to notice. Keep `--jobs 1` documented
for:

- low-memory systems
- tiny imports
- high-entropy imports where worker overhead may not help
- deterministic debugging

For WASM, keep the effective default single-threaded unless a future embedding
explicitly enables threaded WASM.
