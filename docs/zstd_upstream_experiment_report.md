# zstd-rs Upstream Compression Experiment Report

Date: 2026-05-22

Repository under test: `/tmp/zstd-rs-upstream`

## Objective

Measure the pure-Rust `ruzstd` encoder changes discussed during the compression
research work and decide which changes are worth submitting upstream.

## Benchmark Method

All `ruzstd` variants were benchmarked through the same external release-mode
path-dependency harness in `/tmp/zstd-upstream-bench-run`. Each fixture was
compressed with `CompressionLevel::Fastest` after 3 warmup iterations, then
timed over 30 measured iterations.

Native zstd comparison used `/usr/bin/zstd -q -1` for size only. Native CLI
timing was not mixed into the CPU totals because process and file I/O overhead
make it a different benchmark shape.

Raw artifacts:

- `/tmp/zstd-upstream-bench-run/all-experiments.csv`
- `/tmp/zstd-upstream-bench-run/all-experiment-totals.csv`
- `/tmp/zstd-upstream-bench-run/zstd-cli-sizes.csv`

## Experiments

| Variant | Description | Submit? |
| --- | --- | --- |
| `raw-fallback` | Emit a raw block when fastest compression would expand it. | Yes |
| `literal-choices` | Choose the smallest literal section among raw, RLE, new Huffman, and previous Huffman. | Maybe |
| `huffman-maxheight` | Port the C zstd max-height idea so overlong Huffman trees are limited instead of falling back to rank-only weights. | Yes |
| `huffman-depth-probe` | Try each allowable Huffman table depth and keep the smallest emitted literal section. | No |
| `fse-predefined` | Force predefined FSE sequence tables. | No |
| `fse-oracle` | Benchmark-only oracle that tries predefined and encoded FSE sequence table combinations and keeps the smallest section. | No |

## Aggregate Results

| Variant | Total compressed bytes | Delta vs master | Aggregate measured ns | CPU delta vs master |
| --- | ---: | ---: | ---: | ---: |
| `master` | 1,116,962 | 0 | 40,808,252 | 0.0% |
| `raw-fallback` | 1,116,954 | -8 | 40,336,334 | -1.2% |
| `literal-choices` | 1,108,812 | -8,150 | 42,278,659 | +3.6% |
| `huffman-maxheight` | 1,097,645 | -19,317 | 40,524,198 | -0.7% |
| `huffman-depth-probe` | 1,097,637 | -19,325 | 46,713,246 | +14.5% |
| `fse-predefined` | 1,268,847 | +151,885 | 36,502,871 | -10.6% |
| `fse-oracle` | 1,097,629 | -19,333 | 74,346,322 | +82.2% |

Native `zstd -1` total size for the same fixtures was 772,083 bytes, so the
remaining gap is still large after the best Rust-side experiments.

## Size Matrix

| Fixture | Master | Raw fallback | Literal choices | Huffman max-height | zstd -1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `zeros_128k` | 17 | 17 | 17 | 17 | 26 |
| `repeated_text_128k` | 141 | 141 | 140 | 140 | 78 |
| `similar_text_blocks_1m` | 130,236 | 130,236 | 130,168 | 126,423 | 61,395 |
| `json_logs_4m` | 519,555 | 519,555 | 511,482 | 504,060 | 243,577 |
| `xorshift_8k` | 8,209 | 8,205 | 8,205 | 8,205 | 8,206 |
| `xorshift_64k` | 65,553 | 65,549 | 65,549 | 65,549 | 65,550 |
| `xorshift_128k` | 131,088 | 131,088 | 131,088 | 131,088 | 131,088 |
| `xorshift_256k` | 262,163 | 262,163 | 262,163 | 262,163 | 262,163 |

## Conclusions

Submit `raw-fallback` first. It is small, already isolated, prevents avoidable
expansion on incompressible blocks, and has focused tests.

Submit `huffman-maxheight` next, but as its own patch after a careful human
review. It is the strongest measured size improvement with no measured aggregate
CPU regression in this harness. It also directly mirrors the upstream C zstd
strategy: keep the frequency-sensitive Huffman tree and repair overlong code
lengths to the zstd maximum instead of abandoning the tree.

Hold `literal-choices` unless the maintainer wants the full literal mode cleanup
before Huffman max-height. It is correct and tested, but the standalone benefit
is modest and it adds candidate-selection complexity. If submitted, keep it as a
separate patch.

Reject `huffman-depth-probe`. It only saved 8 bytes over `huffman-maxheight` on
the aggregate fixture set and cost about 14.5% more CPU.

Reject the FSE experiments for now. Predefined-only FSE is faster but causes
large text regressions. The oracle proves the best cheap-looking win is only 16
bytes on repeated text and costs far too much CPU. A future FSE patch would need
a cheap estimator before it is worth upstreaming.

The remaining native zstd gap is probably not primarily Huffman literal
encoding. The next research area should be match finding and sequence
generation quality, because native zstd remains roughly 2x smaller on structured
JSON/text fixtures while incompressible fixtures already match closely.
