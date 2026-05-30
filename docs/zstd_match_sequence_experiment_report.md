# zstd-rs Match and Sequence Experiment Report

Date: 2026-05-22

Repository under test: `/tmp/zstd-rs-upstream`

## Objective

Investigate whether the remaining gap to native `zstd -1` is caused by match
finding, sequence generation, or both.

## Method

Each variant was based on the current Huffman max-height patch and benchmarked
with the same release-mode path-dependency harness used for the earlier
upstream experiments. Each fixture was compressed with
`CompressionLevel::Fastest` after 3 warmup iterations, then timed over 30
measured iterations.

Native zstd comparison used `/usr/bin/zstd -q -1` for size only.

Raw artifacts:

- `/tmp/zstd-upstream-bench-run/minmatch4.csv`
- `/tmp/zstd-upstream-bench-run/hash-overwrite.csv`
- `/tmp/zstd-upstream-bench-run/repcode-offsets.csv`
- `/tmp/zstd-upstream-bench-run/hash-oldest-newest.csv`
- `/tmp/zstd-upstream-bench-run/hash-oldest-newest-repcode.csv`
- `/tmp/zstd-upstream-bench-run/hash-two-packed.csv`
- `/tmp/zstd-upstream-bench-run/hash-two-threshold32.csv`
- `/tmp/zstd-upstream-bench-run/hash-two-threshold64.csv`
- `/tmp/zstd-upstream-bench-run/hash-two-newest-first32.csv`
- `/tmp/zstd-upstream-bench-run/hash-two-newest-first64.csv`
- `/tmp/zstd-upstream-bench-run/hash-two-step2.csv`
- `/tmp/zstd-upstream-bench-run/current-huffman-step2.csv`
- `/tmp/zstd-upstream-bench-run/current-profile-optimized2.csv`
- `/tmp/zstd-upstream-bench-run/hash-one-mul.csv`
- `/tmp/zstd-upstream-bench-run/current-profile-hash1.csv`
- `/tmp/zstd-upstream-bench-run/match-sequence-totals.csv`

## C zstd Guidance

The native fast matcher in `lib/compress/zstd_fast.c` uses a more active hash
table than `ruzstd` currently does: it updates hash entries as it scans, checks
recent candidates, handles repeat offsets, and extends matches backward before
storing a sequence.

References:

- https://github.com/facebook/zstd/blob/dev/lib/compress/zstd_fast.c
- https://github.com/facebook/zstd/blob/dev/lib/compress/zstd_compress.c

## Experiments

| Variant | Description | Outcome |
| --- | --- | --- |
| `minmatch4` | Drop minimum match length from 5 to 4 and hash 4 bytes. | Reject. It creates too many short sequences and worsens structured text size. |
| `hash-overwrite` | Always replace the single hash candidate with the newest suffix. | Reject as-is. It improves JSON/text, but regresses repeated text badly. |
| `repcode-offsets` | Encode zstd repeat-offset symbols when the raw matcher offset matches offset history. | Reject for now. It passes tests but does not change size on these fixtures. |
| `hash-oldest-newest` | Keep both the oldest and newest candidate per hash bucket and evaluate both. | Promising, but too slow as implemented. |
| `hash-oldest-newest-repcode` | Combine two-candidate matching with repeat-offset sequence encoding. | Same size as `hash-oldest-newest`; repeat offsets still do not add a measurable size win. |
| `hash-two-packed` | Pack oldest/newest indexes into one `u64` slot so the hash table stays narrow. | Good size, still slower than desired. |
| `hash-two-threshold32` | Check newest only when the current best match is under 32 bytes. | Reject. Faster than full two-candidate matching, but gives back too much size. |
| `hash-two-threshold64` | Check newest only when the current best match is under 64 bytes. | Reject. Same practical result as `hash-two-packed`. |
| `hash-two-newest-first32` | Check newest first and fall back to oldest below 32 bytes. | Reject. Slower than packed oldest-first and worse size. |
| `hash-two-newest-first64` | Check newest first and fall back to oldest below 64 bytes. | Reject. Keeps size but is slower. |
| `hash-two-step2` | Use packed oldest/newest slots and register every other suffix inside matched runs. | Accept as the next matcher candidate. |
| `current-profile-optimized2` | Remove a redundant hash modulo, iterate stride-2 suffix windows directly, cache the hash shift, and remove a checked insert conversion. | Accept. Same size, faster matcher. |
| `hash-one-mul` | Replace the five-multiply suffix hash with one multiply over the first five bytes. | Accept. Faster and smaller on structured fixtures. |
| `current-profile-hash1` | Main patched tree after the profiling-driven matcher changes. | Current recommended matcher patch. |

## Aggregate Results

| Variant | Total compressed bytes | Delta vs Huffman max-height | Aggregate measured ns | Throughput MiB/s |
| --- | ---: | ---: | ---: | ---: |
| `huffman-maxheight` | 1,097,645 | 0 | 40,524,198 | 140.5 |
| `repcode-offsets` | 1,097,645 | 0 | 41,809,551 | 136.2 |
| `hash-overwrite` | 1,054,684 | -42,961 | 41,489,884 | 137.3 |
| `hash-oldest-newest` | 1,032,338 | -65,307 | 51,303,214 | 111.0 |
| `hash-oldest-newest-repcode` | 1,032,338 | -65,307 | 48,999,827 | 116.2 |
| `hash-two-packed` | 1,032,338 | -65,307 | 45,847,949 | 124.2 |
| `hash-two-threshold32` | 1,054,598 | -43,047 | 44,727,513 | 127.3 |
| `hash-two-threshold64` | 1,032,354 | -65,291 | 45,850,727 | 124.2 |
| `hash-two-newest-first32` | 1,039,233 | -58,412 | 48,356,722 | 117.8 |
| `hash-two-newest-first64` | 1,032,345 | -65,300 | 49,324,361 | 115.5 |
| `hash-two-step2` | 1,039,557 | -58,088 | 41,079,658 | 138.6 |
| `current-huffman-step2` | 1,039,557 | -58,088 | 38,856,287 | 146.6 |
| `current-profile-optimized2` | 1,039,557 | -58,088 | 32,979,753 | 172.7 |
| `hash-one-mul` | 992,288 | -105,357 | 31,256,763 | 182.2 |
| `current-profile-hash1` | 992,288 | -105,357 | 31,099,865 | 183.1 |

Native `zstd -1` compressed the same fixtures to 772,083 bytes total.

## Key Fixture Results

| Variant | Repeated text 128 KiB | Similar text 1 MiB | JSON logs 4 MiB |
| --- | ---: | ---: | ---: |
| `huffman-maxheight` | 140 | 126,423 | 504,060 |
| `hash-overwrite` | 3,208 | 116,902 | 467,552 |
| `hash-oldest-newest` | 140 | 113,029 | 452,147 |
| `hash-two-step2` | 140 | 114,478 | 457,917 |
| `current-profile-hash1` | 140 | 105,351 | 419,775 |
| `zstd -1` | 78 | 61,395 | 243,577 |

## Conclusions

Match finding is the next real compression-ratio lever. The full two-candidate
experiment saved 65,307 bytes over the Huffman max-height baseline across this
fixture set, and reduced the JSON fixture from 504,060 bytes to 452,147 bytes
without breaking repeated-run compression.

The first two-candidate implementation was too slow, but packing both candidate
indexes into one `u64` slot recovered a significant part of the CPU cost.
Profiling then showed two avoidable matcher costs: a redundant modulo in the
hash key and branch-heavy stride insertion. Removing those kept size unchanged
and reduced the JSON profile from 380.7M to 335.6M callgrind instructions.

The strongest matcher candidate also replaces the five-multiply suffix hash with
one multiply over the first five bytes. That change was both faster and smaller
on this corpus, likely because it reduced harmful hash collisions on structured
fixtures. The current recommended matcher patch is `current-profile-hash1`: it
saves 105,357 bytes over the Huffman max-height baseline and measured 183.1
MiB/s on the aggregate harness.

Repeat-offset sequence encoding is correct on the current full `ruzstd` test
suite in isolation, but it does not improve size on this corpus. Do not submit
it yet. Revisit it after match generation starts producing more local repeated
offsets, or after adding explicit repcode-aware matching.

Do not pursue `minmatch4` or simple hash overwrite. Both explain useful failure
modes, but neither is a good upstream patch.

Submit the matcher change as a separate patch from the Huffman max-height work.
It changes sequence choices and match-index maintenance, so it deserves its own
review and benchmark note.
