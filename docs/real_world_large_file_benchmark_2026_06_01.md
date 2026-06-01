# Real-World Large File Benchmark - 2026-06-01

This run measures the native threaded import path on real local large files
after merge commit `d245c14` (`Merge native archive jobs pipeline`). The goal
was to check whether the synthetic fixture results carry over to large files
that look more like day-to-day archive inputs.

## Environment

```text
Host:              local Linux workstation
Kernel:            Linux 7.0.0-15-generic x86_64 GNU/Linux
CPU:               AMD Ryzen 7 3700X, 8 cores / 16 threads
Rust:              rustc 1.94.1 (e408947bf 2026-03-25)
Lockbox build:     cargo build --release -p lockbox_cli --manifest-path rust/Cargo.toml
Compression:       local ../zstd-rs/ruzstd backend
Raw output:        rust/target/real-world-large-files-20260601/results/summary.tsv
```

The `analyzer-log` source was copied to
`rust/target/real-world-large-files-20260601/snapshots/analyzer.txt` before the
final sweep because the live log was still being appended during the first
attempt.

## Datasets

```text
dataset          bytes        MiB    source shape
---------------  -----------  -----  -----------------------------------------
analyzer-log     1002712956   956.3  UTF-8 analyzer log text
git-pack          261070003   249.0  Git pack v2 object pack
libflutter-so     367060880   350.1  Android ARM64 ELF shared object with DWARF
screencast-mp4    123262990   117.6  MP4 desktop screen recording
```

## Command

```bash
LOCKBOX_IMPORT_TIMINGS=1 \
  /usr/bin/time -f "%e\t%U\t%S\t%P\t%M" \
  rust/target/release/lockbox \
  --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --jobs "$jobs" \
  add "$lockbox" "$source" "/$dataset"
```

Each row created a fresh lockbox. Jobs swept: `1`, `2`, `4`, `6`, `auto`, `8`,
`12`, and `16`. On native builds `auto` is capped at six workers.

## Best Results

```text
dataset          jobs  wall_s  speedup  output_bytes  ratio    rss_kib
---------------  ----  ------  -------  ------------  -------  -------
analyzer-log       12    1.24    7.07x      20413536  0.02036   171180
git-pack            4    2.28    1.11x     261122144  1.00020   336464
libflutter-so      16    2.15    6.63x     109938784  0.29951   286288
screencast-mp4     16    0.24    4.21x      11273312  0.09146   100096
```

Speedup is relative to the same dataset with `--jobs 1`.

## Auto Default

```text
dataset          jobs1_s  auto_s  auto_speedup  best_s  best_jobs
---------------  -------  ------  ------------  ------  ---------
analyzer-log        8.77    1.73         5.07x    1.24         12
git-pack            2.53    2.36         1.07x    2.28          4
libflutter-so      14.25    3.54         4.03x    2.15         16
screencast-mp4      1.01    0.28         3.61x    0.24         16
```

The six-worker `auto` cap remains a good default. It captures most of the
available wall-clock improvement on compressible inputs while keeping memory
lower than the 12- and 16-worker runs. Explicit higher job counts still matter
for large compressible single files.

## Stage Timings

```text
dataset          jobs  add_s    commit_s  read_s   prepare_s  write_s
---------------  ----  -------  --------  -------  ---------  -------
analyzer-log        1   8.7599    0.0055   0.2378     8.2819   0.1478
analyzer-log       12   1.2092    0.0058   0.3854    13.2335   0.1786
git-pack            1   0.9753    1.4054   0.1221     0.2841   0.3926
git-pack            4   0.7659    1.3617   0.0965     0.5825   0.4168
libflutter-so       1  13.5670    0.6111   0.2600    13.0421   0.1653
libflutter-so      16   1.6840    0.3916   0.4765    25.3170   0.3964
screencast-mp4      1   0.9565    0.0508   0.0512     0.8689   0.0171
screencast-mp4     16   0.1761    0.0552   0.0220     1.4056   0.0140
```

`prepare_s` is accumulated worker time, so it can exceed wall time when work is
parallelized.

## Verification

Representative outputs were extracted and compared byte-for-byte:

```text
analyzer-log     jobs=16  ok
git-pack         jobs=4   ok
libflutter-so    jobs=16  ok
screencast-mp4   jobs=16  ok
```

## Conclusions

- Compressible large files benefit strongly from threading. The analyzer log
  improved from 8.77 s to 1.24 s, and the Flutter shared object improved from
  14.25 s to 2.15 s.
- `--jobs auto` is the right default for normal use: it gets roughly 4-5x on
  the larger compressible files without pushing memory as high as 12 or 16
  jobs.
- `--jobs 12` or `--jobs 16` is useful when the user explicitly wants maximum
  throughput for large compressible files and can spend the extra memory.
- Already-packed data is dominated by write and commit costs. The Git pack was
  effectively incompressible for Lockbox, ended slightly larger due archive
  overhead, and only improved from 2.53 s to 2.28 s.
- If we want another performance pass, the best target is not more compression
  threads. It is the page publication/write/commit path for packed or
  incompressible inputs, plus a possible heuristic to avoid expensive
  compression scheduling when the input is already compressed.
