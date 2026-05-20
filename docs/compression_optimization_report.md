# Compression Optimization Research Report

Date: 2026-05-21

Baseline branch: `experiment/compression-group-manifest`

Baseline commit: `12bdd2d Compact compression frame metadata`

## Executive Summary

The current branch has already made the largest low-risk metadata gains:
compressed frame manifests, encoded metadata page sizing, TOC varints, and
front-coded TOC paths. The repeated-small archive comparison improved from
145,504 bytes to 128,096 bytes after the TOC varint/path work, about 12.0%.

The next work should be treated as a set of independent experiments. Each
candidate needs a hypothesis, measurement, and keep/remove decision. If a
candidate does not clearly improve size or speed, remove it to avoid format
complexity.

Recommendation after this pass:

1. Keep shared TOC compression-frame descriptors.
2. Keep 2 MiB bulk small-file compression frames.
3. Keep 2 MiB large-file compression frames.
4. Keep zstd level 3 only for `BulkImport` compression frames.
5. Keep frame-grouped parallel directory extraction.
6. Keep the uncompressed-frame direct-slice read fast path.
7. Do not implement segment delta-varints yet; current frames almost always
   have one physical segment, so descriptor-to-descriptor deltas are the only
   plausible remaining delta variant.
8. Keep dedupe, dictionaries, semi-solid grouping, and multi-threading as
   separate research tracks with their own measurements.
9. Stop single-threaded format-tuning for now. The remaining measured size
   candidates either produced no artifact change or traded too much range-read
   performance for tiny size wins.

## Baseline Results

Latest archive comparison:

| Fixture | Lockbox bytes | Best archive-compression bytes | Current reading |
| --- | ---: | ---: | --- |
| repeated-small | 97,376 | 48,495 | Lockbox beats GPG/zlib, but not solid zstd |
| text-tree | 2,929,760 | 1,126,606 | Archive-wide compression still wins |
| mixed-tree | 17,037,408 | 16,862,451 | Close to archive tools |
| high-entropy | 67,131,488 | 67,172,282 | Lockbox is slightly smaller than zstd19+GPG |
| dvault-source | 304,224 | 179,158 | Archive-wide compression still wins |

Interpretation:

- Lockbox is now strong on repeated-small files while preserving indexing and
  recovery metadata.
- The remaining gap on text/source fixtures is primarily the difference between
  indexed compression frames and solid archive compression.
- High-entropy data is already near the practical floor.
- Further wins are likely to be incremental unless we accept solid-archive
  tradeoffs.

## Research Protocol

Run each idea as a separate branch or temporary commit. Record results in
`docs/benchmark_history.md`.

Controls:

- Compare every experiment to commit `12bdd2d`.
- Run the same fixture set and commands for every size experiment.
- Do not combine features until each one has an individual result.
- Preserve recovery tests as a gate, not as an optional benchmark.
- Remove any implementation that adds format complexity without a clear result.

Common measurements:

- `bash rust/tools/compare_archive_compression.sh`
- `cargo test --workspace`
- Focused recovery tests for TOC loss and damaged records.
- Large-file perf runs for add, extract, and range-read latency.
- Directory extraction wall time and max RSS for shared-frame workloads.

## Measurements Completed In This Pass

These measurements were taken as single local runs. Treat small timing
differences as directional only; size differences are deterministic for these
fixtures.

### Lockbox-Only Fixture Baseline

This reran only the Lockbox rows from the archive fixture set. External
GPG/zstd rows from the benchmark history are unchanged.

| Fixture | Bytes | Add seconds | Max RSS KiB |
| --- | ---: | ---: | ---: |
| repeated-small | 128,096 | 0.44 | 18,740 |
| text-tree | 3,496,032 | 0.40 | 21,324 |
| mixed-tree | 17,042,528 | 0.25 | 78,220 |
| high-entropy | 67,140,704 | 0.64 | 75,136 |
| dvault-source | 350,304 | 0.03 | 9,240 |

### Accepted Combined Stack

This is the final measured stack from this pass: shared TOC descriptors, 2 MiB
bulk small-file frames, 2 MiB large-file frames, and zstd level 3 for
`BulkImport` compression frames.

| Fixture | Bytes | Add seconds | Max RSS KiB |
| --- | ---: | ---: | ---: |
| repeated-small | 97,376 | 0.38 | 20,960 |
| text-tree | 2,929,760 | 0.48 | 21,932 |
| mixed-tree | 17,037,408 | 0.28 | 71,196 |
| high-entropy | 67,131,488 | 0.67 | 77,020 |
| dvault-source | 304,224 | 0.04 | 8,236 |

Outcome: compared with the `12bdd2d` baseline, the final stack improves
repeated-small by 24.0%, text-tree by 16.2%, and dvault-source by 13.2%, while
keeping high-entropy effectively unchanged.

### Follow-Up Exhaustion Sweep

The next sweep used commit `afaf754` as the baseline and searched for further
single-threaded size/speed wins.

| Candidate | Decision | Result |
| --- | --- | --- |
| TOC descriptor-to-descriptor delta varints | Reject | No fixture byte change |
| Bulk zstd level 2 | Reject | Loses text/source size wins |
| Bulk zstd level 4 | Reject | Text-tree regresses by about 93 KiB vs level 3 |
| Bulk zstd level 5 | Reject | Text-tree regresses by about 89 KiB vs level 3 and is slower |
| 3 MiB bulk frames | Reject | No meaningful size win over 2 MiB |
| 4 MiB bulk frames | Reject | About 2 KiB total fixture win with higher RSS |
| 3 MiB large-file frames | Reject | Tiny size win, worse zero-file add/extract and worse range reads |
| 4 MiB large-file frames | Reject as default | Tiny zero-file size win, worse range reads and randomish size |
| Uncompressed-frame direct slice and owned cache insert | Keep | Improves incompressible read/extract speed |

Accepted speed result:

| Workload | Before | After |
| --- | ---: | ---: |
| 100 MiB randomish 1 MiB range read | 7.00ms | 5.93ms |
| 100 MiB randomish extract | 431.3ms | 373.2ms |
| High-entropy directory extract | 0.53-0.55s | 0.51s |

Conclusion: no further low-risk single-threaded size gains were found. The
remaining high-potential ideas are larger design tracks: dictionaries,
semi-solid groups, dedupe, and multi-threaded import.

### Shared TOC Descriptor Estimate

A temporary synthetic TOC estimator modeled 4,096 files of 25,600 bytes with
40 files per shared compression frame.

| Encoding | Estimated TOC bytes |
| --- | ---: |
| Current chunk-local frame metadata | 310,658 |
| Shared frame descriptor table | 116,275 |
| Estimated saving | 194,383 |
| Estimated saving ratio | 62.6% |

Outcome: H1 is strongly worth implementing as a real prototype. This estimate
does not directly translate to whole-lockbox bytes because TOC pages are
compressed and padded, but it shows that the repeated metadata is large enough
to justify a measured implementation.

### Bulk Small-File Frame Size Sweep

Only `BULK_IMPORT_SMALL_FILE_COMPRESSION_FRAME_BYTES` changed.

| Bulk frame target | repeated-small | text-tree | mixed-tree | high-entropy | dvault-source |
| --- | ---: | ---: | ---: | ---: | ---: |
| 512 KiB | 142,432 | 3,506,272 | 17,047,648 | 67,140,704 | 351,328 |
| 1 MiB baseline | 128,096 | 3,496,032 | 17,042,528 | 67,140,704 | 350,304 |
| 2 MiB | 114,784 | 3,491,936 | 17,038,432 | 67,131,488 | 350,304 |
| 4 MiB | 115,808 | 3,491,936 | 17,038,432 | 67,130,464 | 350,304 |

Repeated-small extraction from the produced artifacts:

| Bulk frame target | Extract seconds | Max RSS KiB |
| --- | ---: | ---: |
| 512 KiB | 0.35 | 151,164 |
| 1 MiB baseline | 0.37 | 166,720 |
| 2 MiB | 0.43 | 193,792 |
| 4 MiB | 1.44 | 281,224 |

Outcome: 2 MiB is the best candidate from this sweep. It reduces
repeated-small bytes by 10.4% versus 1 MiB, with an extraction RSS increase of
about 16.2%. 4 MiB is not worth it as a default: it is not smaller than 2 MiB
on repeated-small and has much worse extraction time/RSS.

### Large-File Frame Size Sweep

Only `FILE_COMPRESSION_FRAME_BYTES` changed. The workload was a 100 MiB file.

| Large frame target | Pattern | Lockbox bytes | Add | Extract stream | 1 MiB range read |
| --- | --- | ---: | ---: | ---: | ---: |
| ~1 MiB baseline | zero | 24,672 | 267.14ms | 175.38ms | 3.68ms |
| 2 MiB | zero | 15,456 | 160.00ms | 88.53ms | 2.40ms |
| 4 MiB | zero | 12,384 | 176.21ms | 89.64ms | 5.10ms |
| ~1 MiB baseline | randomish | 104,891,488 | 447.86ms | 588.90ms | 12.43ms |
| 2 MiB | randomish | 104,881,248 | 447.22ms | 316.78ms | 6.94ms |
| 4 MiB | randomish | 104,888,416 | 462.28ms | 212.98ms | 9.09ms |

Outcome: 2 MiB is the best balanced large-file candidate. 4 MiB compresses
zero data slightly smaller and extracts randomish data fastest in this single
run, but 2 MiB has better range-read latency and nearly the same randomish
size. A larger sample is needed before changing the default.

### Current Extraction Mode Baseline

The `perf` small-file scenario uses the interactive small-file target, not CLI
BulkImport, so this is a speed-shape measurement rather than an archive-size
measurement.

| Mode | Extract seconds | Notes |
| --- | ---: | --- |
| Stream to sink | 1.912 | Single handle, sequential |
| Directory extract | 0.961 | File-backed extraction can parallelize |

Outcome: current directory extraction is already much faster than sequential
stream extraction on this workload. A compression-frame grouping prototype
should be measured against directory extraction, not just sequential stream
extraction.

### Commit And Metadata Baselines

| Workload | Commit | Lockbox bytes | Notes |
| --- | ---: | ---: | --- |
| Append/delete, 5,000 initial + 1,000 appended/replaced | 76.33ms | 1,696,864 | Commit path baseline |
| Metadata, 10,000 env vars + 16 MiB large file | 2.05ms | 17,316,960 | Metadata sizing baseline |

Outcome: commit/metadata CPU is not yet the obvious bottleneck in these small
local runs. Profile before optimizing H6/H7.

### Zstd Dictionary Feasibility Probe

This did not modify Lockbox. It trained a zstd dictionary from fixture samples
and compressed files independently with and without the dictionary.

| Fixture | Independent zstd -1 | zstd -1 with trained dictionary | Outcome |
| --- | ---: | ---: | --- |
| text-tree | 1,890,678 | 2,100,782 | dictionary worsened size |
| dvault-source | 295,533 | 248,761 | dictionary improved size by 15.8% |

Outcome: dictionary compression is workload-sensitive. It is worth a later
targeted experiment for source-like corpora, but it is not a safe default based
on this simple training method.

### Lockbox Zstd Level Sweep

Only the default zstd level changed. The baseline uses level 1.

| Level | repeated-small | text-tree | dvault-source | Add-time reading |
| --- | ---: | ---: | ---: | --- |
| 1 baseline | 128,096 | 3,496,032 | 350,304 | fastest baseline |
| 3 | 115,808 | 2,934,880 | 304,224 | small slowdown |
| 6 | 113,760 | 3,018,848 | 298,080 | slower on text/source |

Outcome: zstd level 3 is promising for a `BulkImport` or archive profile. It
improved all three measured size rows and was best for `text-tree`. Level 6
helped repeated/source size further but regressed `text-tree` compared with
level 3 and cost more time.

## H1: Shared TOC Compression-Frame Descriptors

Hypothesis:

Moving repeated compression-frame metadata from each chunk into a per-TOC-leaf
descriptor table will reduce TOC size, especially for many small files sharing
the same compression frame, without weakening recovery.

Mechanism:

- Store frame id, compression, decompressed length, compressed length, digest,
  and segment refs once per compression frame per TOC leaf.
- Store each chunk as path/file offsets plus a local descriptor index.
- Leave the manifest-bearing file-data segment unchanged.

Measurement:

- Unit: TOC round-trip with many files sharing one frame.
- Corruption: invalid descriptor index must fail closed.
- Recovery: remove/corrupt TOC and confirm recovery still uses file-data
  manifests.
- Benchmark: archive comparison with emphasis on `repeated-small`,
  `text-tree`, and `dvault-source`.

Decision rule:

- Keep if repeated-small improves by at least 5% with no open/list/extract
  regression and no recovery regression.
- Remove if the gain is below noise or TOC split/merge logic becomes fragile.

Preliminary conclusion:

This is the best next candidate. It directly targets known repeated metadata
while preserving recovery, because recovery remains anchored in file-data
segments rather than TOC descriptors.

Measured outcome:

- Synthetic estimator: 310,658 current TOC bytes vs 116,275 estimated bytes
  with shared descriptors, a 62.6% TOC-encoding reduction on the modeled
  repeated-small shape.
- Implemented result:

| Fixture | Baseline bytes | H1 bytes | Add seconds | Max RSS KiB |
| --- | ---: | ---: | ---: | ---: |
| repeated-small | 128,096 | 110,688 | 0.44 | 17,892 |
| text-tree | 3,496,032 | 3,495,008 | 0.40 | 21,648 |
| mixed-tree | 17,042,528 | 17,041,504 | 0.26 | 77,320 |
| high-entropy | 67,140,704 | 67,140,704 | 0.66 | 75,196 |
| dvault-source | 350,304 | 350,304 | 0.03 | 9,168 |

- A first implementation made TOC grouping too expensive because it recomputed
  whole candidate-leaf descriptor tables during grouping. Replacing that with
  an incremental encoded-length estimator restored the long compatible-update
  test to 4.63s.
- Full workspace tests passed after the estimator fix.
- Conclusion: keep H1. It improves repeated-small by 13.6% before any
  frame-size or compression-level changes and preserves recovery because
  file-data segment manifests remain authoritative.

## H2: Delta-Varint Segment References

Hypothesis:

Delta-coding physical segment references will shrink TOC frame descriptors
because page offsets, object ids, and segment offsets are clustered or
monotonic.

Mechanism:

- Within a frame descriptor, store the first segment as absolute values.
- Store later page offsets, object ids, and segment offsets as checked deltas.
- Consider a "same page length as previous" marker only if measured repetition
  justifies it.

Measurement:

- Unit: multi-segment large frames round-trip.
- Corruption: overflowed delta reconstruction must fail closed.
- Benchmark: archive comparison plus large-file perf.
- Safety: large-file recovery after TOC loss.

Decision rule:

- Keep if it measurably reduces mixed/large TOC size after H1.
- Remove if H1 already captures most of the benefit or delta decode adds
  meaningful fragility.

Preliminary conclusion:

Worth testing, but it should follow H1. Delta coding before shared descriptors
could measure repeated metadata noise rather than the actual value of deltas.

Measured outcome:

- Structural finding: with the current 4 MiB decompressed compression-frame
  limit and page segment capacity near 8 MiB, the measured small-file and
  large-file frames are represented by one physical segment each. Segment-delta
  coding therefore has no practical payload to shrink in the accepted stack.
- Descriptor-to-descriptor deltas may still be useful because frame ids, page
  offsets, and object ids often move monotonically across descriptors, but that
  is a separate format change from segment deltas.
- Descriptor-to-descriptor deltas were implemented as a prototype after H1 and
  measured against the fixture set. Every fixture had the same final artifact
  size as the `afaf754` baseline.
- Conclusion: reject H2 for now. The compressed/padded TOC pages absorb the
  small descriptor-table encoding change, so it does not justify extra format
  complexity.

## H3: Bulk Small-File Frame Size Sweep

Hypothesis:

Increasing bulk small-file compression-frame size from 1 MiB to 2 MiB or 4 MiB
will improve compression ratio on repeated/text-like small-file imports, but may
increase extraction RSS and delete rewrite cost.

Current setting:

- `BULK_IMPORT_SMALL_FILE_COMPRESSION_FRAME_BYTES = 1 MiB`
- hard decompressed compression-frame limit = 4 MiB

Measurement:

- Test 512 KiB, 1 MiB, 2 MiB, and 4 MiB.
- Run archive comparison for each.
- Measure directory extraction wall time and max RSS for repeated-small.
- Measure delete/replace behavior for a file inside a shared frame.

Decision rule:

- Keep 2 MiB or 4 MiB only if size improves materially without unacceptable RSS
  or delete/rewrite cost.
- Keep 1 MiB if larger targets produce mostly benchmark-only wins.

Preliminary conclusion:

1 MiB is the conservative default. 2 MiB is the most plausible improvement.
4 MiB may be appropriate only for a bulk/archive profile because the earlier
trial reduced size but raised extraction RSS.

Measured outcome:

- 2 MiB produced the best repeated-small size: 114,784 bytes vs 128,096 bytes
  baseline.
- 4 MiB did not beat 2 MiB on repeated-small and made extraction much worse.
- After H1, applying 2 MiB bulk frames improved repeated-small again from
  110,688 bytes to 97,376 bytes. Text-tree moved from 3,495,008 to 3,490,912
  bytes, mixed-tree from 17,041,504 to 17,037,408, and high-entropy from
  67,140,704 to 67,131,488.
- Repeated-small extraction of the 2 MiB artifact measured 0.16s with about
  190,680 KiB RSS before the later extraction grouping change.
- Conclusion: keep 2 MiB as the bulk import small-file frame target. Reject
  4 MiB as the default.

## H4: Larger Large-File Frames

Hypothesis:

Increasing large-file compression-frame size from about 1 MiB to 2 MiB or 4 MiB
will improve compression ratio and reduce metadata for compressible large files,
but will increase range-read amplification.

Current setting:

- `FILE_COMPRESSION_FRAME_BYTES = 1020 KiB`
- hard decompressed compression-frame limit = 4 MiB

Measurement:

- Test about 1 MiB, 2 MiB, and 4 MiB.
- Patterns: zero, randomish, and text-like generated large files.
- Measure add time, lockbox bytes, full extract, and 1 MiB middle range read.

Decision rule:

- Keep a larger default only if compressible large-file savings justify slower
  range reads.
- Do not exceed the 4 MiB decompressed-frame limit without a separate security
  review.

Preliminary conclusion:

Do not use single huge frames as the default. A 2 MiB or 4 MiB frame may be a
reasonable bounded tradeoff, but arbitrary whole-file frames would weaken the
random-access model and decompression-bomb boundary.

Measured outcome:

- 2 MiB improved both zero and randomish 100 MiB runs versus the current ~1 MiB
  setting.
- 4 MiB gave the smallest zero artifact but had worse range-read latency than
  2 MiB.
- Implemented 2 MiB result:

| Pattern | Logical bytes | Lockbox bytes | Add | Extract | 1 MiB range read |
| --- | ---: | ---: | ---: | ---: | ---: |
| zero | 104,857,600 | 15,456 | 162.3ms | 190.0ms | 2.50ms |
| randomish | 104,857,600 | 104,881,248 | 449.1ms | 431.3ms | 7.00ms |

- Conclusion: keep 2 MiB as the large-file frame target. It is a bounded
  random-access compromise; do not move to whole-file frames by default.

## H5: Extraction Ordering By Compression Frame

Hypothesis:

Grouping full-directory extraction by compression-frame id will reduce repeated
reassembly/decompression and lower extract time or RSS on shared-frame
workloads.

Mechanism:

- Build the existing extraction plan normally.
- Internally group file slices by compression-frame id.
- Decode each frame once and write all requested slices from it.
- Preserve output correctness and extraction policy behavior.

Measurement:

- Repeated-small directory extract.
- Mixed-tree directory extract.
- Memory extraction repeat mode with and without decoded-frame cache.

Decision rule:

- Keep if extract time or RSS improves beyond the current decoded-frame cache.
- Remove if the cache already captures the benefit.

Preliminary conclusion:

Good speed experiment. It should not affect file size or format. It is worth
testing after H1/H3 because larger shared frames make extraction ordering more
important.

Measured outcome:

- Current directory extraction is already faster than sequential stream
  extraction in the file-backed small-file perf run: 0.961s vs 1.912s.
- The implemented prototype keeps entries from the same first compression frame
  in the same parallel worker so each worker clone can reuse its decoded-frame
  cache.

| Variant | Runs | Extract seconds | Max RSS KiB |
| --- | ---: | --- | --- |
| Before frame-grouped parallel extraction | 3 | 0.14-0.15 | 192,576-195,088 |
| After frame-grouped parallel extraction | 3 | 0.11 | 145,196-145,412 |

- Conclusion: keep H5. It improves repeated-small extraction speed and RSS
  without a format change.

## H6: Commit/TOC Rebuild Optimization

Hypothesis:

Commit time can be reduced by avoiding unnecessary TOC entry cloning and
re-encoding during grouping and compatible updates.

Measurement:

- Criterion TOC create/append/delete across leaf split/merge boundaries.
- `LOCKBOX_PERF_SCENARIO=append-delete` at 50k/10k scale.
- Allocation profiling if timing shows a bottleneck.

Decision rule:

- Keep changes that reduce commit time without making crash consistency harder
  to reason about.
- Avoid speculative refactors without profiling evidence.

Preliminary conclusion:

Profile first. The current benchmark pressure is mostly size and extraction
behavior, not proven TOC CPU cost.

Measured outcome:

- Append/delete baseline commit was 76.33ms for 5,000 initial files plus 1,000
  appended/replaced files.
- Conclusion: profile before implementation; this is not the next size win.

## H7: Metadata Page Sizing Reuse

Hypothesis:

Metadata page sizing may do redundant encode/compress work. Reusing the encoded
body between sizing and writing could reduce commit CPU without changing file
size.

Measurement:

- Add counters or a focused benchmark around `page_size_for_encoded_objects`.
- Compare current sizing/write path against a prototype that carries encoded
  page bodies through to write.

Decision rule:

- Keep only if metadata sizing is a real hotspot.
- Remove if it complicates page-cache ownership for little measurable win.

Preliminary conclusion:

Measure before implementing. Encoded-size page sizing was a major size win; a
reuse optimization is only justified if its CPU cost shows up in profiling.

Measured outcome:

- Metadata baseline commit was 2.05ms for 10,000 env vars plus a 16 MiB file.
- Conclusion: no evidence yet that page-sizing reuse is worth extra cache
  complexity.

## H8: Dedupe

Hypothesis:

Content dedupe could reduce repeated-data size beyond compression, especially
for duplicate files or duplicate chunks, but the CPU, index, refcount, privacy,
and recovery costs may outweigh the benefit.

Measurement:

- Separate branch and separate design note.
- Compare fixed-size chunk dedupe and content-defined chunking on repeated and
  realistic corpora.
- Measure add CPU, memory, lockbox bytes, delete/refcount cost, and recovery.
- Include a privacy analysis for equality leakage inside one lockbox.

Decision rule:

- Do not merge unless it gives a large size win on realistic corpora and has a
  clear recovery/refcount story.

Preliminary conclusion:

Do not include dedupe in the compression-frame optimization branch. It is a
separate research project.

## H9: Multi-Threaded Import

Hypothesis:

A bounded worker pipeline can improve import throughput by parallelizing read,
validation, and compression-frame construction, while leaving page allocation
and commit publication single-threaded.

Measurement:

- Only after single-threaded format choices settle.
- Measure recursive add throughput, peak RSS, and crash-consistency complexity.

Decision rule:

- Keep only with bounded memory and unchanged commit ordering guarantees.

Preliminary conclusion:

Defer. It is plausible, but it will obscure single-threaded format results if
started now.

## External Technique Survey

This section lists known techniques from compression, backup, and archival
systems that may help. These should be researched before implementation, and
each should be rejected if it conflicts with Lockbox's random-access,
recoverability, or security goals.

### H10: Zstd Dictionaries For Small Frames

External basis:

- Zstandard's manual explicitly calls out dictionaries as useful for improving
  compression ratio on small data, with prepared dictionaries reducing repeated
  startup cost for bulk processing.
- Python's `compression.zstd` documentation and Rust `zstd::dict`
  documentation describe dictionary training for many small chunks.

Hypothesis:

Training or deriving a dictionary for a directory import could improve
text/source/small-file compression without using solid archive compression.

Measurement:

- Build a prototype that samples the first N small files in a `BulkImport`.
- Train or choose a dictionary, then compress subsequent compression frames
  using that dictionary.
- Compare `text-tree`, `dvault-source`, and repeated-small against the current
  frame compressor.
- Measure dictionary storage overhead, decode setup cost, and recovery
  requirements.

Decision rule:

- Keep only if dictionary storage plus decode complexity produces a material
  size win on text/source fixtures.
- Reject if dictionaries require too much per-lockbox policy state or make
  recovery brittle.

Preliminary conclusion:

Promising for text/source fixtures, but not a quick change. It needs a clear
story for dictionary storage, authentication, recovery, and compatibility with
the current pure-Rust zstd backend.

Measured outcome:

- External zstd dictionary probe improved `dvault-source` independent-file
  compression by 15.8%, but worsened `text-tree` by 11.1%.
- Conclusion: dictionary compression is workload-sensitive. Research further
  only as an explicit profile or trained-per-corpus experiment.

### H11: Seekable Zstd-Style Framing

External basis:

- Zstd seekable-format implementations split data into independent compressed
  frames with an index so readers can decompress only the relevant frame rather
  than the whole file.

Hypothesis:

Lockbox's current compression-frame model is already close to a seekable zstd
design. Studying seekable zstd may improve frame indexing, footer/table layout,
and range-read tradeoffs.

Measurement:

- Compare Lockbox's frame manifest and TOC layout against seekable zstd frame
  tables.
- Prototype any table compaction ideas as TOC descriptor changes, not as a raw
  seekable-zstd adoption.
- Measure range-read amplification and metadata size.

Decision rule:

- Adopt layout ideas only if they preserve encrypted page-level recovery and
  do not require trusting unauthenticated public frame tables.

Preliminary conclusion:

Useful as design reference, but Lockbox should not simply adopt seekable zstd.
Lockbox needs encrypted metadata, authenticated pages, deletion/redaction, and
file-level recovery semantics beyond a read-only compressed stream.

### H12: Content-Defined Chunking And Dedupe

External basis:

- Borg uses content-defined chunking for deduplicating encrypted backup
  repositories.
- Restic uses Rabin-fingerprint content-defined chunks, with small files kept
  unsplit and larger blobs targeted around 1 MiB.
- FastCDC and later CDC work target faster boundary detection while preserving
  dedupe quality.

Hypothesis:

CDC could reduce size for duplicate or shifted content across files and across
versions, outperforming compression alone on repeated corpora.

Measurement:

- Separate branch only.
- Test fixed-size chunks, Rabin CDC, and FastCDC-style boundary detection.
- Measure add CPU, memory, lockbox bytes, delete/refcount cost, and recovery.
- Include corpora with exact duplicates, shifted large files, source trees, and
  high-entropy data.

Decision rule:

- Continue only if realistic corpora show large wins that justify chunk index,
  refcount, privacy, and recovery complexity.

Preliminary conclusion:

High potential, high complexity. This is not an opportunistic optimization.
Keep it as a separate research project.

### H13: Chunking Privacy And Metadata Leakage

External basis:

- Restic's design notes discuss attacks where observable chunk sizes from
  content-defined chunking can leak information, and describe mitigations such
  as randomizing chunk placement in pack files.
- Recent CDC security papers discuss attacks against content-defined chunking in
  backup services.

Hypothesis:

If Lockbox adopts CDC or dedupe, chunk sizes, pack placement, and equality
signals may leak information even if payloads remain encrypted.

Measurement:

- Before implementing dedupe, write a threat model covering same-lockbox
  equality leakage, cross-lockbox leakage, chunk-size leakage, and chosen-input
  attacks.
- Test whether encrypted page packing hides enough placement information.

Decision rule:

- Do not ship CDC/dedupe without a mitigation plan for observable chunk
  metadata.

Preliminary conclusion:

This is the main reason dedupe should remain separate. Compression-frame work
does not currently need to accept these risks.

### H14: Rsync-Style Delta Encoding

External basis:

- The rsync algorithm uses rolling checksums plus strong hashes to identify
  matching blocks between old and new file versions.

Hypothesis:

For updates to large existing files, delta encoding against the previous file
version could reduce write amplification more directly than dedupe.

Measurement:

- Separate update-focused experiment.
- Generate large files with small middle insertions/replacements.
- Compare full rewritten compression frames versus delta records referencing
  prior frames.
- Measure read complexity, compaction cost, and recovery after old-frame
  redaction.

Decision rule:

- Reject unless partial-update workloads are important enough to justify
  retaining and compacting base data.

Preliminary conclusion:

Not a near-term size optimization for archive imports. It may matter later if
Lockbox targets efficient versioned updates.

### H15: Domain-Specific Metadata Codecs

External basis:

- Front-coding, restart intervals, delta coding, and local tables are common in
  sorted-key indexes and columnar metadata encodings.

Hypothesis:

TOC metadata can shrink further by separating repeated fields into local tables
and delta streams instead of encoding each entry as a self-contained record.

Measurement:

- This is effectively the broader family containing H1 and H2.
- Prototype only one metadata transform at a time:
  - local compression-frame descriptor table
  - delta segment refs
  - path restart interval tuning
  - permissions/stored-path local tables
- Measure each transform independently.

Decision rule:

- Keep transforms that produce clear size wins without hurting decode
  robustness.

Preliminary conclusion:

This family is the best fit for Lockbox because it preserves random access,
encryption boundaries, and recovery semantics.

### H16: Adaptive Compression Level Or Strategy

External basis:

- Zstd exposes compression levels and strategies with speed/ratio tradeoffs.
  Higher levels can require more memory and CPU.
- Backup tools such as restic expose compression policy choices like automatic,
  max, or off.

Hypothesis:

Lockbox may gain size on text/source fixtures by using a stronger zstd setting
for selected bulk/archive workloads while keeping level 1 for interactive work.

Measurement:

- Add a temporary compression-level switch for compression frames only.
- Test levels 1, 3, 6, and a high level on text/source/repeated fixtures.
- Measure CPU, RSS, and output bytes.

Decision rule:

- Keep only as a workload-profile option if it gives a meaningful size win.
- Do not make high compression levels the default if they harm interactive
  latency.

Preliminary conclusion:

Worth measuring after metadata experiments. It may help text/source fixtures,
but it will not close the full gap to solid archive compression.

Measured outcome:

- Level 3 improved repeated-small, text-tree, and dvault-source size versus
  level 1.
- Level 6 improved repeated-small and dvault-source further, but was worse than
  level 3 on text-tree and slower.
- Scoped implementation result with H1 and 2 MiB bulk frames:

| Fixture | zstd level 1 bytes | BulkImport zstd level 3 bytes | Add-time reading |
| --- | ---: | ---: | --- |
| repeated-small | 97,376 | 97,376 | 0.37s to 0.38s |
| text-tree | 3,490,912 | 2,929,760 | 0.41s to 0.48s |
| mixed-tree | 17,037,408 | 17,037,408 | 0.25s to 0.28s |
| high-entropy | 67,131,488 | 67,131,488 | 0.64s to 0.67s |
| dvault-source | 350,304 | 304,224 | 0.04s to 0.04s |

- Conclusion: keep zstd level 3 for `BulkImport` compression frames only.
  Do not change page-body metadata compression or interactive compression
  frames from level 1.

### H17: Solid Or Semi-Solid Archive Groups

External basis:

- Archive tools win on text/source fixtures because they compress one large
  stream or much larger context than Lockbox's bounded random-access frames.

Hypothesis:

A semi-solid profile that groups many files into larger independently indexed
compression regions could improve ratio while keeping bounded partial access.

Measurement:

- Treat as a separate profile, not the default.
- Sweep group sizes larger than 4 MiB only if the decompression-bomb security
  model is explicitly revised.
- Measure text/source size, extraction RSS, delete cost, and range-read cost.

Decision rule:

- Keep only as an explicit archive/bulk profile if callers accept reduced
  random-access/update granularity.

Preliminary conclusion:

This is the principled way to chase archive-tool ratios, but it changes product
semantics. Do not mix it with the default indexed format until there is a clear
profile boundary.

## Final Conclusions

The current branch is in a good state to become the baseline for controlled
experiments. The next likely size win is not more generic zstd tuning; it is
removing repeated TOC metadata while leaving recovery metadata in the file-data
segments.

Recommended next sequence:

1. Implement and measure H1.
2. Repeat the 2 MiB H3/H4 constant runs to confirm they are stable.
3. Test zstd level 3 combined with the 2 MiB bulk target as a profile candidate.
4. If H1 wins, only then revisit H2; otherwise drop H2.
5. Try H5 as a speed-only change after frame-size decisions.
6. Profile before attempting H6 or H7.
7. Research H10, H11, H15, and H16 as likely-compatible techniques.
8. Keep H8, H9, H12, H13, H14, and H17 as separate tracks unless the product
   goal explicitly shifts toward backup/archive semantics.

Expected outcome:

- H1 has the highest probability of a useful size win with acceptable risk.
- H2 is now lower priority because current frames usually have one physical
  segment.
- H3/H4 measurements both point at 2 MiB as the best next candidate.
- H5 may improve extraction speed if larger shared frames are kept, but current
  directory extraction is already strong.
- H6/H7 do not yet have evidence justifying implementation.
- H10 dictionary compression is mixed; H16 zstd level 3 is more immediately
  promising for a bulk/archive profile.
- H11 is useful as a reference model, not as a direct adoption target.
- H12/H13/H14/H17 are larger projects, not opportunistic branch work.

## References

- [Zstd manual](https://facebook.github.io/zstd/zstd_manual.html)
- [Zstd format specification](https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md)
- [Zstd seekable-format Rust implementation](https://github.com/rorosen/zeekstd)
- [BorgBackup documentation](https://borgbackup.readthedocs.io/en/stable/)
- [Restic design document](https://github.com/restic/restic/blob/master/doc/design.rst)
- [Restic content-defined chunking introduction](https://restic.net/blog/2015-09-12/restic-foundation1-cdc/)
- [FastCDC paper](https://www.usenix.org/conference/atc16/technical-sessions/presentation/xia)
- [The rsync algorithm](https://rsync.samba.org/tech_report/)
