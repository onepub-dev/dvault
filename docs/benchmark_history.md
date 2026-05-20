# Benchmark History

This file records benchmark runs that are useful for comparing format,
dependency, or implementation changes. Keep each entry self-contained: include
the change being measured, the command, environment, baseline source, and
observed result table.

## 2026-05-20 - TOC Varints, Path Suffixes, and Compressed Manifests

Description: continued the `experiment/compression-group-manifest` branch after
adding varint encoding and front-coded path suffixes to TOC leaves. The file
compression-frame manifest work from the prior entry is still active: segment
payloads store compact frame identity on every segment, the full manifest only
on the first segment, and manifest bytes are compressed when worthwhile.

Commands:

```bash
cd rust/..
bash rust/tools/compare_archive_compression.sh
```

Environment:

- Host: local Linux workstation
- Rust: workspace default toolchain for this checkout
- GPG: 2.4.8
- zstd: system `/usr/bin/zstd`
- Fixture output: `rust/target/archive-comparison/results/summary.tsv`
- Baseline source: the 2026-05-19 expanded archive comparison and compression
  group manifest entries below

Results:

| Fixture | Tool | Logical bytes | Output bytes | Seconds | Max RSS KiB |
| --- | --- | ---: | ---: | ---: | ---: |
| repeated-small | Lockbox | 104,857,600 | 128,096 | 0.36 | 18,720 |
| repeated-small | `tar | gpg` default | 104,857,600 | 463,336 | 1.77 | 5,316 |
| repeated-small | `tar | gpg --compress-algo zlib --compress-level 9` | 104,857,600 | 200,156 | 0.68 | 5,108 |
| repeated-small | `tar | zstd -1 | gpg --compress-algo none` | 104,857,600 | 55,627 | 0.16 | 17,436 |
| repeated-small | `tar | zstd -19 | gpg --compress-algo none` | 104,857,600 | 48,495 | 0.44 | 437,240 |
| text-tree | Lockbox | 30,193,763 | 3,496,032 | 0.57 | 21,412 |
| text-tree | `tar | gpg` default | 30,193,763 | 2,494,015 | 0.37 | 5,228 |
| text-tree | `tar | gpg --compress-algo zlib --compress-level 9` | 30,193,763 | 2,007,625 | 0.57 | 5,212 |
| text-tree | `tar | zstd -1 | gpg --compress-algo none` | 30,193,763 | 1,763,322 | 0.19 | 18,384 |
| text-tree | `tar | zstd -19 | gpg --compress-algo none` | 30,193,763 | 1,126,606 | 25.60 | 116,976 |
| mixed-tree | Lockbox | 21,947,435 | 17,042,528 | 0.39 | 78,192 |
| mixed-tree | `tar | gpg` default | 21,947,435 | 17,019,926 | 0.61 | 5,488 |
| mixed-tree | `tar | gpg --compress-algo zlib --compress-level 9` | 21,947,435 | 16,939,281 | 0.73 | 5,272 |
| mixed-tree | `tar | zstd -1 | gpg --compress-algo none` | 21,947,435 | 16,984,571 | 0.26 | 22,952 |
| mixed-tree | `tar | zstd -19 | gpg --compress-algo none` | 21,947,435 | 16,862,451 | 5.58 | 124,972 |
| high-entropy | Lockbox | 67,108,880 | 67,140,704 | 0.69 | 75,116 |
| high-entropy | `tar | gpg` default | 67,108,880 | 67,299,458 | 1.86 | 5,248 |
| high-entropy | `tar | gpg --compress-algo zlib --compress-level 9` | 67,108,880 | 67,177,002 | 2.11 | 5,276 |
| high-entropy | `tar | zstd -1 | gpg --compress-algo none` | 67,108,880 | 67,174,412 | 0.58 | 22,952 |
| high-entropy | `tar | zstd -19 | gpg --compress-algo none` | 67,108,880 | 67,172,282 | 8.51 | 382,912 |
| dvault-source | Lockbox | 1,039,364 | 350,304 | 0.05 | 9,028 |
| dvault-source | `tar | gpg` default | 1,039,364 | 258,949 | 0.17 | 5,432 |
| dvault-source | `tar | gpg --compress-algo zlib --compress-level 9` | 1,039,364 | 226,736 | 0.22 | 5,468 |
| dvault-source | `tar | zstd -1 | gpg --compress-algo none` | 1,039,364 | 254,388 | 0.16 | 5,272 |
| dvault-source | `tar | zstd -19 | gpg --compress-algo none` | 1,039,364 | 179,158 | 0.38 | 86,888 |

Conclusion:

- TOC varints and front-coded path suffixes reduced the repeated-small Lockbox
  result from 145,504 bytes to 128,096 bytes, about a 12.0% improvement over
  the previous compression-manifest run.
- The same metadata encoding change also shaved smaller amounts from the text,
  mixed, high-entropy, and source-tree fixtures.
- Lockbox now beats default GPG and high-level GPG zlib on the repeated-small
  fixture, but whole-stream `tar | zstd | gpg --compress-algo none` remains
  much smaller because it compresses one archive stream.
- Text/source fixtures still favor archive-wide compression. The current
  Lockbox design is optimizing indexed random access and recovery metadata, not
  solid archive compression.

## 2026-05-19 - Expanded Archive Compression Comparison

Description: added `rust/tools/compare_archive_compression.sh` to generate a
broader fixture set and compare Lockbox against default GPG, high-level GPG
zlib, and external zstd piped into uncompressed GPG. This run is a caution
against over-reading the repeated-small-file result: Lockbox removes its
previous padding floor, but external archive compression is still usually
smaller on text/source data.

Commands:

```bash
cd rust/..
bash rust/tools/compare_archive_compression.sh
```

Environment:

- Host: local Linux workstation
- Rust: workspace default toolchain for this checkout
- GPG: 2.4.8
- zstd: system `/usr/bin/zstd`
- Fixture output: `rust/target/archive-comparison/results/summary.tsv`

Fixtures:

- `repeated-small`: 4,096 files x 25,600 repeated `x` bytes
- `text-tree`: generated JSONL service logs with repeated fields and varied values
- `mixed-tree`: generated markdown, tiny text files, and deterministic AES-CTR binary blobs
- `high-entropy`: deterministic AES-CTR binary blobs
- `dvault-source`: docs plus Rust source/tests/examples/tools from this checkout

Results:

| Fixture | Tool | Logical bytes | Output bytes | Seconds | Max RSS KiB |
| --- | --- | ---: | ---: | ---: | ---: |
| repeated-small | Lockbox | 104,857,600 | 145,504 | 0.41 | 19,232 |
| repeated-small | `tar | gpg` default | 104,857,600 | 463,335 | 0.68 | 5,388 |
| repeated-small | `tar | gpg --compress-algo zlib --compress-level 9` | 104,857,600 | 200,156 | 0.68 | 5,440 |
| repeated-small | `tar | zstd -1 | gpg --compress-algo none` | 104,857,600 | 55,627 | 0.17 | 17,440 |
| repeated-small | `tar | zstd -19 | gpg --compress-algo none` | 104,857,600 | 48,495 | 0.45 | 437,112 |
| text-tree | Lockbox | 30,193,763 | 3,504,224 | 0.37 | 21,748 |
| text-tree | `tar | gpg` default | 30,193,763 | 2,494,015 | 0.40 | 5,428 |
| text-tree | `tar | gpg --compress-algo zlib --compress-level 9` | 30,193,763 | 2,007,626 | 0.59 | 5,176 |
| text-tree | `tar | zstd -1 | gpg --compress-algo none` | 30,193,763 | 1,763,322 | 0.18 | 17,796 |
| text-tree | `tar | zstd -19 | gpg --compress-algo none` | 30,193,763 | 1,126,606 | 26.32 | 116,892 |
| mixed-tree | Lockbox | 21,947,435 | 17,047,648 | 0.28 | 78,460 |
| mixed-tree | `tar | gpg` default | 21,947,435 | 17,019,926 | 0.64 | 5,448 |
| mixed-tree | `tar | gpg --compress-algo zlib --compress-level 9` | 21,947,435 | 16,939,281 | 0.73 | 5,372 |
| mixed-tree | `tar | zstd -1 | gpg --compress-algo none` | 21,947,435 | 16,984,571 | 0.26 | 22,920 |
| mixed-tree | `tar | zstd -19 | gpg --compress-algo none` | 21,947,435 | 16,862,451 | 5.90 | 125,092 |
| high-entropy | Lockbox | 67,108,880 | 67,141,728 | 0.70 | 75,144 |
| high-entropy | `tar | gpg` default | 67,108,880 | 67,299,458 | 1.87 | 5,456 |
| high-entropy | `tar | gpg --compress-algo zlib --compress-level 9` | 67,108,880 | 67,177,002 | 2.04 | 5,536 |
| high-entropy | `tar | zstd -1 | gpg --compress-algo none` | 67,108,880 | 67,174,412 | 0.59 | 22,988 |
| high-entropy | `tar | zstd -19 | gpg --compress-algo none` | 67,108,880 | 67,172,282 | 9.32 | 383,156 |
| dvault-source | Lockbox | 1,039,364 | 351,328 | 0.03 | 9,164 |
| dvault-source | `tar | gpg` default | 1,039,364 | 258,947 | 0.17 | 5,456 |
| dvault-source | `tar | gpg --compress-algo zlib --compress-level 9` | 1,039,364 | 226,735 | 0.22 | 5,412 |
| dvault-source | `tar | zstd -1 | gpg --compress-algo none` | 1,039,364 | 254,388 | 0.15 | 5,456 |
| dvault-source | `tar | zstd -19 | gpg --compress-algo none` | 1,039,364 | 179,158 | 0.42 | 86,852 |

Conclusion:

- Lockbox is not generally beating archive compression. It beats default GPG on
  the repeated-small fixture because zstd plus compact metadata removes the old
  padding floor, but `tar | zstd` is still much smaller there.
- On text-like and source-tree fixtures, archive-wide compression wins
  materially because it shares dictionary/context across file boundaries and
  path metadata.
- On high-entropy data, all tools are close to raw size. Lockbox is in the same
  range, but uses more memory because it is building encrypted indexed pages.
- Issue #26 is relevant: larger archive-style compression frames improve some
  ratios, but decoders must enforce a hard decompressed-frame ceiling before
  decompression. This branch now rejects declared compression frames above 4 MiB
  and validates zstd's declared content size before `decode_all`.

## 2026-05-19 - Compression Group Manifest and Encoded Metadata Pages

Description: branch experiment on `experiment/compression-group-manifest`.
Compression-frame segment payloads now store compact frame identity on every
segment, store the full manifest only on the first segment, and compress the
manifest bytes when worthwhile. `BulkImport` uses a 1 MiB small-file
compression-frame target. Normal metadata pages are now sized from the encoded
stored page body, not from the uncompressed object stream, so highly compressed
TOC leaves no longer occupy 128 KiB physical pages.

Commands:

```bash
cd rust
cargo build --release -p lockbox_cli

/usr/bin/time -f 'lockbox-cli-create %e %M' \
  target/release/lockbox --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  create target/bench-tmp/gpg-compare-2/final-1m-encoded-metadata-1779140656.lbx

/usr/bin/time -f 'lockbox-cli-add %e %M' \
  target/release/lockbox --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  add target/bench-tmp/gpg-compare-2/final-1m-encoded-metadata-1779140656.lbx \
  target/bench-tmp/gpg-compare-2/src /

/usr/bin/time -f 'lockbox-cli-extract %e %M' \
  target/release/lockbox --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  extract target/bench-tmp/gpg-compare-2/encoded-metadata-1m-1779140545.lbx \
  --to target/bench-tmp/gpg-compare-2/extract-encoded-1m-1779140545

LOCKBOX_PERF_DIR="$PWD/target/bench-tmp" \
LOCKBOX_PERF_SCENARIO=large \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_LARGE_BYTES=104857600 \
LOCKBOX_PERF_PATTERN=randomish \
LOCKBOX_PERF_EXTRACT=stream \
cargo run -p lockbox_core --example perf --release

cargo test --workspace
cargo test -p lockbox_core --lib repeated_small_files_keep_meaningful_compression -- --ignored --nocapture
cargo test -p lockbox_core --lib moderately_large_zero_file_uses_few_fixed_pages -- --ignored --nocapture
```

Environment:

- Host: local Linux workstation
- Rust: workspace default toolchain for this checkout
- Corpus: 4,096 files x 25,600 repeated `x` bytes, 104,857,600 logical bytes
- Baseline: previous same-day GPG comparison entries below

GPG comparison:

| Tool | Encode time | Max RSS | Output bytes | Ratio |
| --- | ---: | ---: | ---: | ---: |
| Lockbox before bulk-frame experiment | 0.43s | 117,888 KiB | 1,245,280 | 0.012 |
| Lockbox 512 KiB bulk frames | 0.42s | 18,880 KiB | 923,744 | 0.009 |
| Lockbox 1 MiB frames + encoded metadata pages | 0.40s | 19,172 KiB | 145,504 | 0.001 |
| `tar | gpg` default compression | 1.75s | 3,964 KiB | 464,960 | 0.004 |
| `tar | gpg --compress-algo none` | 0.81s | 3,760 KiB | 107,004,045 | 1.021 |

Extraction:

| Tool | Extract time | Max RSS | Files |
| --- | ---: | ---: | ---: |
| Lockbox CLI `extract --to`, 1 MiB bulk target | 0.31s | 172,328 KiB | 4,096 |

Large-file regression check:

| Workload | Add | Commit | Extract stream | Range read | Output bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| 100 MiB randomish large file | 485.56ms | 552.04ms | 642.44ms | 14.44ms | 104,893,536 |

Conclusion:

- The main remaining size problem was compressed metadata page padding, not
  file-data page slack. TOC leaves with about 126 KiB of logical payload were
  compressing to about 12 KiB but still occupying 128 KiB physical pages.
- Sizing metadata pages from encoded stored length reduced this repeated-file
  corpus from 923,744 bytes to 145,504 bytes with the 1 MiB bulk target.
- A 4 MiB bulk target reached 132,192 bytes, but extraction RSS rose to about
  287 MiB in this run. The 1 MiB target is the better current tradeoff.
- Large randomish file size remains effectively unchanged. The page-size
  estimator uses the cheap uncompressed sizing path for file-data pages so large
  writes do not double-encode page bodies.

## 2026-05-18 - Bulk Compression-Frame Size Experiment

Description: branch experiment on `experiment/archive-compression-frames`.
`BulkImport` now uses a 512 KiB small-file compression-frame target while
retaining the larger page-sized staging flush threshold so file-data pages stay
dense. `ReadMostly` and `ExtractMany` can cache decoded compression frames in a
bounded zeroizing cache, and the CLI selects `BulkImport` for directory adds and
read/extract profiles for extraction.

Commands:

```bash
cd rust
cargo build --release -p lockbox_cli

/usr/bin/time -f 'lockbox-cli-create %e %M' \
  target/release/lockbox --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  create target/bench-tmp/gpg-compare-2/experiment-512k-1779093693.lbx

/usr/bin/time -f 'lockbox-cli-add %e %M' \
  target/release/lockbox --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  add target/bench-tmp/gpg-compare-2/experiment-512k-1779093693.lbx \
  target/bench-tmp/gpg-compare-2/src /

/usr/bin/time -f 'lockbox-cli-extract %e %M' \
  target/release/lockbox --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  extract target/bench-tmp/gpg-compare-2/experiment-512k-1779093693.lbx \
  --to target/bench-tmp/gpg-compare-2/extract-512k-1779093693

LOCKBOX_PERF_DIR="$PWD/target/bench-tmp" \
LOCKBOX_PERF_SCENARIO=large \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_LARGE_BYTES=104857600 \
LOCKBOX_PERF_PATTERN=randomish \
LOCKBOX_PERF_EXTRACT=stream \
cargo run -p lockbox_core --example perf --release

cargo test --workspace
cargo test -p lockbox_core --lib repeated_small_files_keep_meaningful_compression -- --ignored --nocapture
cargo test -p lockbox_core --lib moderately_large_zero_file_uses_few_fixed_pages -- --ignored --nocapture
```

Environment:

- Host: local Linux workstation
- Rust: workspace default toolchain for this checkout
- Corpus: 4,096 files x 25,600 repeated `x` bytes, 104,857,600 logical bytes
- Baseline: previous same-day GPG comparison entry below

GPG comparison:

| Tool | Encode time | Max RSS | Output bytes | Ratio |
| --- | ---: | ---: | ---: | ---: |
| Lockbox CLI bulk import, 4 KiB interactive target | 0.43s | 117,888 KiB | 1,245,280 | 0.012 |
| Lockbox CLI bulk import, 512 KiB bulk target | 0.42s | 18,880 KiB | 923,744 | 0.009 |
| `tar | gpg` default compression | 1.75s | 3,964 KiB | 464,960 | 0.004 |
| `tar | gpg --compress-algo none` | 0.81s | 3,760 KiB | 107,004,045 | 1.021 |

Extraction:

| Tool | Extract time | Max RSS | Files |
| --- | ---: | ---: | ---: |
| Lockbox CLI `extract --to`, 512 KiB bulk target | 0.32s | 153,016 KiB | 4,096 |

Large-file regression check:

| Workload | Add | Commit | Extract stream | Range read | Output bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| 100 MiB randomish large file | 448.18ms | 528.34ms | 619.64ms | 12.35ms | 104,888,416 |

Conclusion:

- Larger bulk compression frames reduced this repeated-small-file corpus from
  1,245,280 bytes to 923,744 bytes, a 25.8% size reduction, without slowing the
  CLI add path in this run.
- The remaining gap to compressed GPG is still material: Lockbox is about 2.0x
  the compressed GPG output on this synthetic corpus. That points at metadata
  overhead and the lack of whole-archive compression context, not page slack.
- Keeping the bulk flush threshold at the page-sized streaming threshold matters.
  A short-lived 512 KiB flush creates many underfilled physical pages because
  each flush owns its own page writer.
- The decoded compression-frame cache is opt-in through read/extract workload
  profiles and zeroizes cached plaintext on eviction/drop.

## 2026-05-18 - Compression Frames, Segments, and GPG Comparison

Description: renamed the file-data compression unit to a compression frame and
renamed page-bounded stored pieces to compression-frame segments. The serialized
TOC/manifest field model now uses `compression_frame_*` names, and the segment
payload marker was moved to `LBCS` because this is a pre-release format with no
backward-compatibility requirement. File-data and normal metadata pages now use
variable physical sizes rounded to a 1 KiB quantum, capped at 8 MiB for
file-data and 128 KiB for metadata. The performance example reports page slack
from page inspection so page-fill behavior is visible in benchmark output.

Commands:

```bash
cd rust
cargo build --release -p lockbox_cli
mkdir -p target/bench-tmp/gpg-compare-2/src
perl -e 'print "x" x 25600' > target/bench-tmp/gpg-compare-2/template.bin
for i in $(seq -w 0 4095); do
  cp target/bench-tmp/gpg-compare-2/template.bin \
    target/bench-tmp/gpg-compare-2/src/file-$i.bin
done

/usr/bin/time -f 'lockbox-cli-create %e %M' \
  target/release/lockbox --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  create target/bench-tmp/gpg-compare-2/current.lbx
/usr/bin/time -f 'lockbox-cli-add %e %M' \
  target/release/lockbox --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  add target/bench-tmp/gpg-compare-2/current.lbx \
  target/bench-tmp/gpg-compare-2/src /

GNUPGHOME="$PWD/target/bench-tmp/gpg-compare-2/gnupg" \
  /usr/bin/time -f 'default %e %M' sh -c \
  'tar -C target/bench-tmp/gpg-compare-2/src -cf - . |
   gpg --batch --yes --pinentry-mode loopback --passphrase lockbox-bench
   --symmetric --cipher-algo AES256
   -o target/bench-tmp/gpg-compare-2/default.tar.gpg'

GNUPGHOME="$PWD/target/bench-tmp/gpg-compare-2/gnupg" \
  /usr/bin/time -f 'none %e %M' sh -c \
  'tar -C target/bench-tmp/gpg-compare-2/src -cf - . |
   gpg --batch --yes --pinentry-mode loopback --passphrase lockbox-bench
   --symmetric --cipher-algo AES256 --compress-algo none
   -o target/bench-tmp/gpg-compare-2/none.tar.gpg'

LOCKBOX_PERF_DIR="$PWD/target/bench-tmp" \
LOCKBOX_PERF_SCENARIO=small \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_FILES=4096 \
LOCKBOX_PERF_FILE_BYTES=25600 \
LOCKBOX_PERF_EXTRACT=stream \
cargo run -p lockbox_core --example perf --release

LOCKBOX_PERF_DIR="$PWD/target/bench-tmp" \
LOCKBOX_PERF_SCENARIO=large \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_LARGE_BYTES=104857600 \
LOCKBOX_PERF_PATTERN=randomish \
LOCKBOX_PERF_EXTRACT=stream \
cargo run -p lockbox_core --example perf --release
```

Environment:

- Host: local Linux workstation
- Rust: workspace default toolchain for this checkout
- GPG: 2.4.8 with isolated `GNUPGHOME` under `target/bench-tmp`
- Corpus: 4,096 files x 25,600 repeated `x` bytes, 104,857,600 logical bytes

GPG comparison:

| Tool | Encode time | Max RSS | Output bytes | Ratio |
| --- | ---: | ---: | ---: | ---: |
| Lockbox CLI bulk import | 0.43s | 117,888 KiB | 1,245,280 | 0.012 |
| `tar | gpg` default compression | 1.75s | 3,964 KiB | 464,960 | 0.004 |
| `tar | gpg --compress-algo none` | 0.81s | 3,760 KiB | 107,004,045 | 1.021 |

Page slack from the same logical small-file corpus:

| Workload | Pages | File-data pages | Metadata pages | Unused bytes | Unused ratio | File-data unused ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4,096 x 25,600 repeated files | 12 | 1 | 11 | 7,938 | 0.013 | 0.002 |
| 100 MiB randomish large file | 17 | 13 | 4 | 4,342 | 0.000 | 0.000 |

Conclusion:

- On highly repeated data, current Lockbox is faster than `tar | gpg` with
  default compression and much smaller than uncompressed GPG, but whole-stream
  GPG compression still wins the size test.
- Variable-size pages remove the pathological fixed-page tail cost. The
  repeated small-file corpus is about 98.7% full overall and the randomish
  large-file corpus is effectively full, with only a few KiB of page slack.
- The current small-file compression-frame target keeps read/delete behavior
  sane, but it cannot compete with whole-archive compression on repeated
  cross-file content.

## 2026-05-17 - Compression-Frame Manifest Layout

Description: replaced page-level file-data compression with compression-frame
bundles. Small files are packed into bounded shared compression frames with a
compact binary manifest; file-data pages now store their object stream
uncompressed so file bytes are compressed exactly once. A first Criterion run
with 1 MiB small-file bundles exposed poor repeated small-file extraction and
shared-compression-frame delete behavior, so the small-file compression-frame
target was tuned to 4 KiB while large streaming compression frames remain about
1 MiB.

Commands:

```bash
cd rust
TMPDIR="$PWD/target/bench-tmp" cargo bench -p lockbox_core --bench performance small_files
TMPDIR="$PWD/target/bench-tmp" cargo bench -p lockbox_core --bench performance large_file
TMPDIR="$PWD/target/bench-tmp" cargo bench -p lockbox_core --bench performance append_delete
cargo test -p lockbox_core --lib repeated_small_files_keep_meaningful_compression -- --ignored --nocapture
cargo test -p lockbox_core --lib moderately_large_zero_file_uses_few_fixed_pages -- --ignored --nocapture
```

Environment:

- Host: local Linux workstation
- Rust: workspace default toolchain for this checkout
- Benchmark harness: Criterion, sample size 10 per benchmark
- Baseline source: local Criterion history from the previous format runs
- Note: the full unfiltered bench run was stopped after the harness filled
  `/tmp` with generated `lockbox-bench-*.lbx` files; focused reruns used
  `target/bench-tmp`.

Results:

| Benchmark | Mean |
| --- | ---: |
| `small_files/add_commit_1000x1k` | 10.809 ms |
| `small_files/extract_stream_1000x1k` | 42.139 ms |
| `small_files/extract_directory_1000x1k` | 110.81 ms |
| `large_file/add_commit_16m_randomish` | 112.33 ms |
| `large_file/range_read_1m_middle` | 9.8309 ms |
| `append_delete/append_delete_replace_commit` | 237.64 ms |

Compression regression checks:

- `repeated_small_files_keep_meaningful_compression`: passed
- `moderately_large_zero_file_uses_few_fixed_pages`: passed

Conclusion:

- Small-file writes and extraction are viable with 4 KiB small-file compression
  frames.
- Large-file randomish writes remain reasonable, but range reads now pay the
  compression frame reassembly/digest/decode cost and should be watched.
- Shared-compression-frame delete is correct and redacts old content, but
  remains the main performance tradeoff because removing one slice requires
  rewriting the surviving slices in that compression frame.

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
  are substantially slower because compression dominates page creation.
- Read/extract/list paths are flat to materially faster in this run, especially
  the large-file range read.
- The next performance step should profile compression during commit and decide
  whether to tune `oxiarc-zstd`, skip compression for incompressible/high-entropy
  file pages earlier, or make compression level/strategy configurable while
  still defaulting to a C-free backend.

## 2026-05-09 - High-Entropy Compression Skip

Description: profiled the large low-compressibility write path with
`cargo flamegraph`; the resolved samples were dominated by
`oxiarc_zstd::lz77::MatchFinder`. Added a page-body precheck that samples
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
- Compressible small-file packing remains intentionally unchanged; those page
  bodies still compress well.
- Several small read/extract results moved backward in this run. Those paths do
  not execute the new entropy check while reading, so treat them as a signal for
  follow-up profiling rather than proof of causation.
- The next step is to profile the post-optimization large write path and the
  mixed-tree commit path to identify the remaining dominant cost.

## 2026-05-09 - Deterministic File-Page Offsets

Description: after the entropy skip, the large low-compressibility profile
shifted from zstd to file writes, page encoding, stream generation, and page
crypto. Removed a write-side round trip where file pages were read back
through storage/decrypt/decode immediately after writing only to recover
`page_inner_offset` values. Those offsets are deterministic from the file
page payload layout, so they are now computed before writing.

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

## 2026-05-09 - Explicit Write-Through Page Cache

Description: the deterministic-offset change removed an accidental readback
that had been warming the page cache. Added explicit cache insertion for
newly written decoded pages. This keeps writes going through the page
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
  saved after deterministic file-page offsets and before write-through cache

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
page compression level from zstd level 3 to level 1 and benchmarked the
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
  saved after explicit write-through page caching
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
  write-heavy paths that still compress page bodies.
- `toc_structure/separator_update_5000` regressed in this run, so future TOC
  profiling should verify whether that is noise, cache state, or a real
  compression-level interaction.
- Keep level 1 as the default unless production-size lockbox benchmarks show a
  meaningful space regression.

## 2026-05-09 - Production-Scale File-Backed Compression Check

Description: ran the file-backed performance example against production-sized
inputs after profiling. The initial 1 GiB check showed that compression was not
reducing lockbox size for large files because chunks were sized by uncompressed
payload and every physical page is fixed at 8 MiB. Added a stronger
test that compares fixed-page usage for compressible and high-entropy large
files, then changed large-file chunking so a compressed page can
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
- Backend: file-backed lockbox storage
- Profile artifact: `rust/target/flamegraph-file-small-50k.svg`

Results after compressed logical chunking:

| Scenario | Logical bytes | Lockbox bytes | Add | Commit | Extract/Delete | Range read | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 GiB zero large file | 1,073,741,824 | 159,383,616 | 2.770s | 15.158ms | 2.454s | 112.452ms | 0.148 |
| 1 GiB randomish large file | 1,073,741,824 | 1,098,907,712 | 6.412s | 17.466ms | 1.787s | 6.749ms | 1.023 |
| 100k x 1 KiB files, 5 memory extracts | 102,400,000 | 142,606,400 | 205.323ms | 1.299s | 612.156ms | n/a | 1.393 |
| 50k initial + 10k append/delete/replace | 122,880,000 | 184,549,440 | 21.900ms | 516.788ms | 25.625ms | n/a | 1.502 |

Conclusion:

- The old large-file behavior failed a meaningful compression standard:
  1 GiB zero and 1 GiB randomish files both used the same lockbox size.
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

## 2026-05-09 - Page-Packed Compression Frames and Object-Indexed Cache

Description: after moving to the final page-packed file-data model, reran the
production-scale file-backed example. The first post-format run showed the
right compression behavior for highly compressible data, but exposed two
performance issues: page-fit checks were doing full encode/encrypt/compress
work for every tentative file segment, and small-file extraction scanned every
object in a cached page for each file. Replaced tentative fit checks with a
fixed page-budget calculation, tuned large-compression frame size so high-entropy
frames pack tightly into 8 MiB pages, and added an object-id index to cached
decoded pages.

Commands:

```bash
cd rust
LOCKBOX_PERF_DIR="$PWD/.tmp-bench" \
LOCKBOX_PERF_SCENARIO=large \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_LARGE_BYTES=1073741824 \
LOCKBOX_PERF_PATTERN=zero \
cargo run -p lockbox_core --example perf --release

LOCKBOX_PERF_DIR="$PWD/.tmp-bench" \
LOCKBOX_PERF_SCENARIO=large \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_LARGE_BYTES=1073741824 \
LOCKBOX_PERF_PATTERN=randomish \
cargo run -p lockbox_core --example perf --release

LOCKBOX_PERF_DIR="$PWD/.tmp-bench" \
LOCKBOX_PERF_SCENARIO=small \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_FILES=100000 \
LOCKBOX_PERF_FILE_BYTES=1024 \
LOCKBOX_PERF_EXTRACT=memory \
LOCKBOX_PERF_EXTRACT_REPEAT=5 \
cargo run -p lockbox_core --example perf --release

LOCKBOX_PERF_DIR="$PWD/.tmp-bench" \
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
- Backend: file-backed lockbox storage
- Scratch directory: `rust/.tmp-bench`
- Verification: `cargo test --workspace` before this optimization, and
  `cargo test -p lockbox_core` after the optimization

Pre-fix observations from this run:

| Scenario | Result |
| --- | --- |
| 1 GiB randomish large file | 37.103s add, 1,249,902,656 bytes, 1.164 ratio |
| 20k x 1 KiB files, one memory extract | 28.476s extract |
| 100k x 1 KiB files, 5 memory extracts | aborted after several minutes |

Results after page-budget fitting and object-indexed cache:

| Scenario | Logical bytes | Lockbox bytes | Add | Commit | Extract/Delete | Range read | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 GiB zero large file | 1,073,741,824 | 25,165,888 | 842.507ms | 8.712ms | 675.549ms | 962.597us | 0.023 |
| 1 GiB randomish large file | 1,073,741,824 | 1,098,907,712 | 5.919s | 9.240ms | 1.371s | 1.882ms | 1.023 |
| 100k x 1 KiB files, 5 memory extracts | 102,400,000 | 50,331,712 | 216.496ms | 1.433s | 800.422ms | n/a | 0.492 |
| 50k initial + 10k append/delete/replace | 122,880,000 | 58,720,320 | 23.830ms | 467.940ms | 26.019ms | n/a | 0.478 |

Comparison to the previous production-scale file-backed run:

| Scenario | Previous | New | Change |
| --- | ---: | ---: | ---: |
| 1 GiB zero add | 2.770s | 842.507ms | -69.6% |
| 1 GiB zero extract | 2.454s | 675.549ms | -72.5% |
| 1 GiB zero lockbox bytes | 159,383,616 | 25,165,888 | -84.2% |
| 1 GiB randomish add | 6.412s | 5.919s | -7.7% |
| 1 GiB randomish ratio | 1.023 | 1.023 | flat |
| 100k small-file extract x5 | 612.156ms | 800.422ms | +30.8% |
| 100k small-file lockbox bytes | 142,606,400 | 50,331,712 | -64.7% |
| Append/delete commit | 516.788ms | 467.940ms | -9.5% |
| Append/delete lockbox bytes | 184,549,440 | 58,720,320 | -68.2% |

Conclusion:

- The final page-packed model removes the fixed-page compression floor for
  highly compressible large files while preserving high-entropy size behavior.
- Page-budget fitting removes encode/encrypt/compress work from tentative
  packing checks; this was the main large-file write regression.
- Object-indexed decoded pages remove the O(files x objects-per-page) small-file
  extraction path. A 20k-file extraction dropped from 28.476s to 31.065ms.
- Small-file extraction is slightly slower than the previous 100k baseline but
  uses far less disk, because many tiny files now co-reside in fewer physical
  pages. The remaining extraction cost is acceptable for this run, but should be
  watched in future cold-cache directory extraction benchmarks.

## 2026-05-10 - Archive Compression Comparison

Description: compared the current lockbox page-packed compression behavior with
common archive formats on the same local corpus classes. The corpus was kept
locally under `rust/.tmp-archive-compare` for follow-up inspection. Large
lockbox inputs were generated with the performance harness. Traditional archive
inputs were real files/directories so the tools could run normally.

Commands:

```bash
cd rust
mkdir -p .tmp-archive-compare/{zero,random,small}
truncate -s 1073741824 .tmp-archive-compare/zero/blob.bin

cd .tmp-archive-compare/zero
zip -q -9 zero.zip blob.bin
tar --zstd -cf zero.tar.zst blob.bin
7z a -bd -mx=9 zero.7z blob.bin

cd ../random
# Corpus generated as 1 GiB of high-entropy bytes.
zip -q -9 random.zip blob.bin
tar --zstd -cf random.tar.zst blob.bin
7z a -bd -mx=9 random.7z blob.bin

cd ../small
# 100k files, each 1 KiB of repeated bytes.
zip -q -9 -r small.zip .
tar --zstd -cf small.tar.zst --exclude=small.tar.zst --exclude=small.zip --exclude=small.7z .
7z a -bd -mx=9 -xr!small.zip -xr!small.tar.zst -xr!small.7z small.7z .
```

Environment:

- Host: `Linux slayer4 6.11.0-26-generic x86_64`
- CPU: `AMD Ryzen 7 3700X 8-Core Processor`, 8 cores / 16 threads
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Tools: `/usr/bin/zip`, `/usr/bin/zstd`, `/usr/bin/tar`, `/usr/bin/7z`
- Local corpus path retained: `rust/.tmp-archive-compare`

Results:

| Corpus | Tool | Archive bytes | Ratio | Time |
| --- | --- | ---: | ---: | ---: |
| 1 GiB zero file | lockbox | 25,165,888 | 0.023 | 0.822s add |
| 1 GiB zero file | ZIP `-9` | 1,042,217 | 0.001 | 4.11s |
| 1 GiB zero file | tar.zst | 33,761 | 0.00003 | 1.66s |
| 1 GiB zero file | 7z `-mx=9` | 156,739 | 0.00015 | 3.95s |
| 1 GiB high-entropy file | lockbox | 1,098,907,712 | 1.023 | 5.871s add |
| 1 GiB high-entropy file | ZIP `-9` | 1,073,915,736 | 1.000 | 24.94s |
| 1 GiB high-entropy file | tar.zst | 1,073,766,937 | 1.000 | 1.38s |
| 1 GiB high-entropy file | 7z `-mx=9` | 1,073,808,403 | 1.000 | 42.43s |
| 100k x 1 KiB repeated files | lockbox | 50,331,712 | 0.492 | 1.329s commit |
| 100k x 1 KiB repeated files | ZIP `-9` | 16,700,539 | 0.163 | 9.16s |
| 100k x 1 KiB repeated files | tar.zst | 1,113,522 | 0.011 | 2.87s |
| 100k x 1 KiB repeated files | 7z `-mx=9` | 288,304 | 0.003 | 4.60s |

Conclusion:

- ZIP, tar.zst, and 7z beat lockbox on extreme repeated data because they store
  variable-length compressed archive streams. Lockbox deliberately stores fixed
  encrypted pages with recoverable object boundaries.
- Lockbox is competitive on high-entropy size and much faster than ZIP/7z for
  the measured high-entropy write path, but tar.zst is faster when encryption,
  random access, recovery, and key management are not required.
- The many-small-file repeated corpus shows the expected tradeoff: lockbox is
  faster than ZIP in this run and far smaller than raw data, but whole-archive
  compressors win the ratio test by exploiting repetition across file and
  metadata boundaries.
- Compression regression coverage now lives in
  `rust/lockbox_core/tests/compression_regression.rs`. The tests are ignored by
  default to keep local CI fast, and GitHub Actions runs them explicitly in the
  `compression regression corpus` job.
- The GitHub job stores deterministic source corpus files in `actions/cache`
  under `rust/.ci-compression-corpus`, keyed by
  `LOCKBOX_COMPRESSION_CORPUS_VERSION`. On a cache miss it rebuilds the corpus
  with `cargo run --release -p lockbox_core --example compression_corpus --
  .ci-compression-corpus`, then runs the ignored regression tests against that
  cached corpus.

## 2026-05-10 - Commit-Time Dirty Pages and Redaction

Description: measured the disk-backed path after moving dirty page writes to
commit time, renaming page terminology, adding visualization support, and
adding delete/env redaction that zeroes the original page data before freed
pages are reused. This run used the file backend rather than the memory backend.

Validation before profiling:

```bash
cd rust
cargo fmt --all
cargo test --workspace
```

The workspace test suite passed. The agent IPC, compression regression, and
endian interop tests remain explicitly ignored unless their dedicated CI jobs
run them.

Disk-backed benchmark commands:

```bash
cd rust
LOCKBOX_PERF_DIR="$PWD/.tmp-bench" \
LOCKBOX_PERF_SCENARIO=small \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_FILES=50000 \
LOCKBOX_PERF_FILE_BYTES=1024 \
LOCKBOX_PERF_EXTRACT=memory \
LOCKBOX_PERF_EXTRACT_REPEAT=5 \
cargo run -p lockbox_core --example perf --release

LOCKBOX_PERF_DIR="$PWD/.tmp-bench" \
LOCKBOX_PERF_SCENARIO=append-delete \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_INITIAL_FILES=50000 \
LOCKBOX_PERF_APPEND_FILES=10000 \
LOCKBOX_PERF_FILE_BYTES=2048 \
cargo run -p lockbox_core --example perf --release

LOCKBOX_PERF_DIR="$PWD/.tmp-bench" \
LOCKBOX_PERF_SCENARIO=large \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_LARGE_BYTES=134217728 \
LOCKBOX_PERF_PATTERN=randomish \
LOCKBOX_PERF_EXTRACT=memory \
cargo run -p lockbox_core --example perf --release
```

Results:

| Scenario | Logical bytes | Lockbox bytes | Add | Commit | List | Extract/Delete | Range read | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 50k x 1 KiB files, 5 memory extracts | 51,200,000 | 25,165,920 | 123.538ms | 706.034ms | 5.018ms | 385.768ms | n/a | 0.492 |
| 50k initial + 10k append/delete/replace | 122,880,000 | 75,497,568 | 21.743ms | 546.710ms | 6.815ms | 24.471ms | n/a | 0.614 |
| 128 MiB randomish large file | 134,217,728 | 159,383,648 | 265.514ms | 492.412ms | n/a | 87.854ms | 904.272us | 1.188 |

Profiling command:

```bash
cd rust
LOCKBOX_PERF_DIR="$PWD/.tmp-bench" \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_SCENARIO=small \
LOCKBOX_PERF_EXTRACT=memory \
LOCKBOX_PERF_EXTRACT_REPEAT=5 \
LOCKBOX_PERF_FILES=20000 \
LOCKBOX_PERF_FILE_BYTES=1024 \
cargo flamegraph -p lockbox_core --example perf --release \
  -o target/flamegraph-file-small-20k-dirty-pages.svg
```

The profiling run produced
`rust/target/flamegraph-file-small-20k-dirty-pages.svg`. The measured 20k-file
profile run produced:

| Scenario | Logical bytes | Lockbox bytes | Add | Commit | List | Extract/Delete | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 20k x 1 KiB files, 5 memory extracts | 20,480,000 | 25,165,920 | 43.697ms | 270.149ms | 2.028ms | 133.617ms | 1.229 |

The flamegraph was captured without full dependency debuginfo and with kernel
symbol restrictions, so the percentages should be treated as directional. The
visible hotspots were:

- zstd hashing/compression paths (`xxhash`, `ZstdEncoder`, match finder).
- `BTreeMap` subtree cloning.
- memory pressure sampling.
- dirty page flushing, which was visible but not dominant in the small profile.

Conclusion:

- The dirty page cache now has the intended transaction shape: modified pages
  are staged in memory, COW happens at commit, and pages are written once when
  commit flushes the dirty set.
- Redaction adds real work to commits because deleted/replaced file and env data
  is zeroed before the old physical page is returned to the free index. That is
  the right production behavior, but it raises commit cost compared with the
  earlier less secure path.
- Small-file list/extract times are still low. Commit is the main area to keep
  tuning because it now includes packing, TOC updates, free-index updates,
  redaction, page checksum/encryption, and final header publication.
- Next performance candidates are reducing `BTreeMap` cloning during commit,
  coalescing dirty page flush ordering more aggressively, sampling memory
  pressure less often, and improving compression skip heuristics for data that
  zstd cannot shrink meaningfully.

## 2026-05-10 - Performance Target Pass

Description: targeted the visible hotspots from the dirty-page/redaction
profile while preserving the production format and transaction model. Changes:

- Dirty page flush now reads storage length once, reuses a zero-page buffer for
  sparse gaps, and avoids cloning decoded pages before encoding.
- Auto cache sizing samples OS memory pressure every 1024 cache operations
  instead of every 256 operations.
- TOC commit avoids sorting TOC values already ordered by `LogicalPath`.
- TOC internal rebuild no longer performs a linear child-position search for
  each child group.
- Compression entropy probing counts sampled ranges directly instead of
  allocating a temporary sample buffer.
- Incompressible extension detection avoids allocating a lowercased extension.
- Pending small-file bytes are stored as shared immutable data, so commit
  rollback snapshots do not duplicate the staged file corpus.

Disk-backed benchmark commands matched the previous run:

```bash
cd rust
LOCKBOX_PERF_DIR="$PWD/.tmp-bench" \
LOCKBOX_PERF_SCENARIO=small \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_FILES=50000 \
LOCKBOX_PERF_FILE_BYTES=1024 \
LOCKBOX_PERF_EXTRACT=memory \
LOCKBOX_PERF_EXTRACT_REPEAT=5 \
cargo run -p lockbox_core --example perf --release

LOCKBOX_PERF_DIR="$PWD/.tmp-bench" \
LOCKBOX_PERF_SCENARIO=append-delete \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_INITIAL_FILES=50000 \
LOCKBOX_PERF_APPEND_FILES=10000 \
LOCKBOX_PERF_FILE_BYTES=2048 \
cargo run -p lockbox_core --example perf --release

LOCKBOX_PERF_DIR="$PWD/.tmp-bench" \
LOCKBOX_PERF_SCENARIO=large \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_LARGE_BYTES=134217728 \
LOCKBOX_PERF_PATTERN=randomish \
LOCKBOX_PERF_EXTRACT=memory \
cargo run -p lockbox_core --example perf --release
```

Final run results:

| Scenario | Logical bytes | Lockbox bytes | Add | Commit | List | Extract/Delete | Range read | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 50k x 1 KiB files, 5 memory extracts | 51,200,000 | 25,165,920 | 102.417ms | 681.244ms | 5.040ms | 359.722ms | n/a | 0.492 |
| 50k initial + 10k append/delete/replace | 122,880,000 | 75,497,568 | 24.174ms | 525.359ms | 6.058ms | 25.017ms | n/a | 0.614 |
| 128 MiB randomish large file | 134,217,728 | 159,383,648 | 247.933ms | 524.696ms | n/a | 86.357ms | 996.695us | 1.188 |

Comparison to the previous dirty-page/redaction baseline:

| Scenario | Metric | Previous | New | Change |
| --- | --- | ---: | ---: | ---: |
| 50k x 1 KiB files | Add | 123.538ms | 102.417ms | -17.1% |
| 50k x 1 KiB files | Commit | 706.034ms | 681.244ms | -3.5% |
| 50k x 1 KiB files | Extract x5 | 385.768ms | 359.722ms | -6.8% |
| Append/delete/replace | Commit | 546.710ms | 525.359ms | -3.9% |
| Append/delete/replace | List | 6.815ms | 6.058ms | -11.1% |
| 128 MiB randomish | Add | 265.514ms | 247.933ms | -6.6% |
| 128 MiB randomish | Extract | 87.854ms | 86.357ms | -1.7% |

Updated profiling command:

```bash
cd rust
LOCKBOX_PERF_DIR="$PWD/.tmp-bench" \
LOCKBOX_PERF_BACKEND=file \
LOCKBOX_PERF_SCENARIO=small \
LOCKBOX_PERF_EXTRACT=memory \
LOCKBOX_PERF_EXTRACT_REPEAT=5 \
LOCKBOX_PERF_FILES=20000 \
LOCKBOX_PERF_FILE_BYTES=1024 \
cargo flamegraph -p lockbox_core --example perf --release \
  -o target/flamegraph-file-small-20k-perf-pass.svg
```

The profiling run produced
`rust/target/flamegraph-file-small-20k-perf-pass.svg`. The profile workload
reported:

| Scenario | Logical bytes | Lockbox bytes | Add | Commit | List | Extract/Delete | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 20k x 1 KiB files, 5 memory extracts | 20,480,000 | 25,165,920 | 40.983ms | 279.438ms | 1.907ms | 125.960ms | 1.229 |

Conclusion:

- The changes improved every comparable final metric except small variations in
  large-file commit/range timing, which remain dominated by fixed commit work
  and normal local disk noise at this workload size.
- The remaining visible profile cost is mostly allocation/copying around commit
  rollback and TOC materialization, plus zstd internals. Further
  reductions likely require a larger structural change: building TOC leaves from
  borrowed TOC entries and making rollback journal-based instead of
  snapshot-based.

## 2026-05-13 - Workload-Aware Cache Policy Pass

Description: added explicit workload profiles and wired CLI-created initial
imports to `BulkImport`. In that profile, append-only file-data pages are
flushed and dropped from the decoded-page cache as they are written. Metadata,
redaction, TOC, env, free-index, key-directory, and commit-root writes keep the
normal commit-time cache policy.

Verification:

- `cargo test -p lockbox_core`
- `cargo clippy -p lockbox_core --all-targets -- -D warnings`
- `cargo build --release -p lockbox_cli`
- `cargo bench -p lockbox_core --bench performance`

Criterion results:

| Benchmark | Result | Criterion verdict |
| --- | ---: | --- |
| small_files/add_commit_1000x1k | 23.70ms | no change |
| small_files/extract_memory_1000x1k | 1.100ms | +5.2%, regression |
| small_files/extract_directory_1000x1k | 23.54ms | no change |
| mixed_tree/add_commit_mixed | 17.73ms | no change |
| mixed_tree/list_recursive_mixed | 8.19us | -2.1%, improved |
| mixed_tree/extract_directory_mixed | 9.61ms | no change |
| large_file/add_commit_16m_randomish | 78.05ms | within noise |
| large_file/range_read_1m_middle | 133.5us | no change |
| append_delete/append_delete_replace_commit | 36.95ms | no change |
| toc_structure/separator_update_5000 | 47.24ms | no change |
| toc_structure/leaf_split_append_5000 | 30.96ms | no change |
| toc_structure/leaf_merge_delete_5000 | 40.14ms | no change |
| metadata_operations/rename_16m_file_commit | 5.69ms | no change |
| metadata_operations/list_env_1000 | 575.4us | within noise |
| metadata_operations/compact_16m_file_after_delete | 79.13ms | no change |

100 MiB directory comparison used 4,096 files of 25,600 bytes each:

| Tool | Encode time | Max RSS | Output bytes |
| --- | ---: | ---: | ---: |
| Lockbox CLI bulk import | 3.28s | 78,792 KiB | 110,231,648 |
| `tar | gpg` default compression | 3.94s | 3,672 KiB | 105,578,459 |
| `tar | gpg --compress-algo none` | 0.83s | 3,332 KiB | 107,004,045 |

Compared with the previous 100 MiB lockbox/GPG pass, lockbox output size is
unchanged, encode time is slightly higher, and peak RSS dropped from roughly
266 MiB to 79 MiB. The bulk import path now packs small files through a
long-lived `PageObjectPacker` and flushes before the current packed page would
overflow, so it keeps roughly one file-data page plus import metadata resident
instead of the whole source corpus. A density regression test checks that
non-tail file-data pages are not left mostly empty.

## 2026-05-15 - Secure String Store Benchmark and Protection Batching

Description: added Criterion coverage for the page-pooled secure string store
after introducing secret env vars. The benchmark separates secure string
creation, byte-wise append, slice append, and repeated reads with either one
guard per secret or one shared access guard. The first profile showed avoidable
page-protection churn around canary checks, data writes, zeroization, and free.
The secure heap now checks both canaries and performs the data operation inside
one full-allocation page-protection window for those paths.

Command:

```bash
cd rust
cargo bench -p lockbox_core --bench performance secure_string_store
```

An attempted local flamegraph run was blocked by the host kernel's
`perf_event_paranoid=4` setting, so this entry records Criterion timing only
and does not include a profile artifact.

After lowering `perf_event_paranoid` to `1`, local flamegraph capture worked:

- `rust/target/flamegraph-secure-string-store.svg`
- `rust/target/flamegraph-secure-string-store-optimized.svg`

Environment:

- Host: `Linux slayer4 6.11.0-26-generic x86_64`
- CPU: `AMD Ryzen 7 3700X 8-Core Processor`, 8 cores / 16 threads
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Benchmark harness: Criterion, sample size 10 per benchmark
- Baseline source: new benchmark group; comparisons below are within the same
  run

Results:

| Benchmark | Baseline mean | Optimized mean | Change |
| --- | ---: | ---: | ---: |
| `secure_string_store/from_bytes_1000x64` | 74.675 ms | 19.717 ms | -73.6% |
| `secure_string_store/push_byte_64` | 941.14 us | 325.71 us | -65.4% |
| `secure_string_store/extend_slice_64` | 57.249 us | 14.791 us | -74.2% |
| `secure_string_store/read_1000x64_individual_guard` | 6.3705 ms | 6.1294 ms | -3.5% |
| `secure_string_store/read_1000x64_shared_guard` | 107.15 us | 101.81 us | -5.8% |

Conclusion:

- Byte-at-a-time construction is expensive because each append touches the
  protected heap. The CLI secret prompt now appends input in chunks through
  `SecretString::try_extend_from_slice`.
- A shared read-access scope is roughly two orders of magnitude faster than
  creating a scope per string for repeated reads in this workload. Code that
  reads many secrets should use `lockbox_secure::read_access()`.
- Construction still has fixed overhead from secure heap locking and page
  permission changes. The optimized flamegraph still shows `mprotect` as the
  remaining significant secure-store cost, which is expected for protected
  pages. Further reductions would require a larger API or policy change, such
  as a write access guard for batch construction or an explicitly weaker mode.
