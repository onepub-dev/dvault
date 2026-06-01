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

Keep `--jobs auto` as the native default, but cap native automatic worker
selection at six workers. The cap captures most many-file speedups without
paying the RSS and scheduling cost of always using every core. Explicit
`--jobs N` remains available for large single-file imports where the larger
stage-timing sweep kept improving up to 16 workers.

Keep `--jobs 1` documented for:

- low-memory systems
- tiny imports
- high-entropy imports where worker overhead may not help
- deterministic debugging

For WASM, keep the effective default single-threaded unless a future embedding
explicitly enables threaded WASM.

## Follow-Up Stage Timing - 2026-06-01

After reviewing the initial sweep, we added coarse import stage timing behind
`LOCKBOX_IMPORT_TIMINGS=1` and reran larger fixtures across `--jobs 1..16`.

Raw results:

```text
rust/target/jobs-stage-sweep-20260601/results-clean/summary.tsv
```

Larger fixtures:

```text
fixture              logical bytes
repeated-small-200m    209,715,200
text-tree-120m         122,150,245
single-text-256m       268,435,556
high-entropy-128m      134,217,728
```

Best observed wall times:

```text
fixture              jobs_1_wall  best_jobs  best_wall  speedup
repeated-small-200m       1.00s          5      0.44s    2.27x
text-tree-120m            1.42s          6      0.59s    2.41x
single-text-256m          2.07s         16      0.34s    6.09x
high-entropy-128m         1.35s         15      1.24s    1.09x
```

Representative stage timings at the best wall-time point:

```text
fixture              jobs  add_wall  commit  host_read  frame_prepare  page_write
repeated-small-200m     5     0.405   0.033      0.093          0.662       0.003
text-tree-120m          6     0.544   0.043      0.060          1.409       0.036
single-text-256m       16     0.338   0.002      0.126          3.641       0.067
high-entropy-128m      15     1.239   0.003      0.034          0.249       0.958
```

Interpretation:

- The threaded compression path is working. The single large compressible file
  scales from 2.07 s to 0.34 s and reaches about 10 effective CPU cores.
- The many-small-file fixtures flatten around 2-3 effective cores because the
  CLI still walks, stats, opens, and reads files serially, and the ordered
  writer still drains prepared frames through one mutation path.
- High-entropy input barely benefits from more threads because compression
  preparation is cheap and page write/encoding dominates.

Next likely performance targets:

- Add bounded parallel directory walk/stat/read for bulk imports.
- Split page payload encoding/encryption from ordered page publication so
  high-entropy imports can use more cores without breaking commit ordering.
- Keep the ordered writer responsible for final offsets, TOC updates, and commit
  root publication.
