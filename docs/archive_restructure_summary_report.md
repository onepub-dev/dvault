# Archive Restructure And Upstream Encoder Report

Date: 2026-05-22

## Executive Summary

Two tracks ran in parallel:

1. A subagent prepared a small upstreamable `ruzstd` patch in
   `/tmp/zstd-rs-upstream` on branch `compression-ratio-spike`.
2. This repository gained a clean-slate archive v2 design note and a probe that
   estimates pack-layout and metadata effects.

The main conclusion is conservative: a format restructure is useful for
simplifying updates, recovery, and future compression policy, but it does not by
itself close the size gap to `tar | zstd | gpg`. The dominant size gap is still
the pure-Rust zstd encoder quality, especially on text/source trees.

## Upstream `ruzstd` Track

The subagent changed `/tmp/zstd-rs-upstream`, not this repository.

Branch:

- `compression-ratio-spike`

Changed files:

- `ruzstd/src/encoding/levels/fastest.rs`
- `ruzstd/src/encoding/levels/fastest_tests.rs`
- `ruzstd/src/encoding/levels/mod.rs`
- `ruzstd/examples/compression_ratio.rs`
- `Changelog.md`

Patch summary:

- `Fastest` now emits a raw block when the compressed payload is not smaller
  than the source block.
- This avoids avoidable expansion on incompressible blocks.
- The patch is deliberately small and suitable for upstream review.

Measured impact from the subagent's generated fixture example:

| Fixture | Before Bytes | After Bytes | Impact |
| --- | ---: | ---: | ---: |
| `zeros_128k` | 17 | 17 | unchanged |
| `repeated_text_128k` | 141 | 141 | unchanged |
| `xorshift_8k` | 8,209 | 8,205 | -4 |
| `xorshift_64k` | 65,553 | 65,549 | -4 |
| `xorshift_128k` | 131,088 | 131,088 | unchanged |
| `xorshift_256k` | 262,163 | 262,163 | unchanged |

Subagent verification:

- `cargo fmt --all`
- `cargo test -q -p ruzstd fastest_does_not_expand_incompressible_blocks_past_raw_size`
- `cargo test -q -p ruzstd test_encode_corpus_files_compressed_our_decompressor`
- `cargo test -q -p ruzstd --examples`
- `cargo test -q -p ruzstd`

Recommendation:

- This is worth submitting upstream because it is correct, tiny, and easy to
  review.
- It is not a meaningful fix for our main gap. The next upstream work should
  target match finding, literal Huffman/table choices, and level strategy.
- Because `ruzstd` documents an AI contribution policy, a human should review
  the diff and own the PR communication.

## Archive V2 Work

Added:

- `docs/archive_v2_restructure_proposal.md`
- `rust/lockbox_core/examples/archive_v2_probe.rs`

The v2 proposal is an append-only framed object store:

- pack frames for file bytes
- metadata delta frames for path/file/extent tables
- checkpoint frames for current roots
- optional dictionary/redaction frames
- independent recovery at frame and pack granularity

The probe estimates:

- compressed data bytes
- current-like path-repeating manifest bytes
- v2 columnar metadata bytes
- v2 numeric pack-manifest bytes
- total estimated bytes
- compression time
- read amplification

Command used:

```text
cargo run --offline -q -p lockbox_core --example archive_v2_probe -- <fixture>
```

Results were written to:

- `rust/target/archive-comparison/results/archive_v2_probe.tsv`

## Selected Results

Baseline current Lockbox results are from:

- `rust/target/archive-comparison/results/summary.tsv`

| Fixture | Current Lockbox Bytes | Best V2 Estimate | Delta | Notes |
| --- | ---: | ---: | ---: | --- |
| `repeated-small` | 97,376 | 167,397 | worse | Current format already handles this very well. |
| `text-tree` | 2,929,760 | 2,936,280 | roughly equal | Layout changes do not fix oxiarc text ratio. |
| `mixed-tree` | 17,037,408 | 17,048,782 | roughly equal | Incompressible bytes dominate. |
| `high-entropy` | 67,131,488 | 67,111,776 | slightly better | Mostly fewer metadata/frame bytes. |
| `dvault-source` | 304,224 | 297,964 | 2.1% smaller | Columnar metadata plus one source pack helps a little. |

The best v2 estimates above still use the current oxiarc compression backend.
They therefore isolate format/packing effects from encoder effects.

## Pack Size Findings

Larger packs reduce metadata bytes but rapidly increase read amplification.

Examples:

- `text-tree` compressed data changed only from about 2,899,197 bytes at 512 KiB
  packs to 2,890,828 bytes at 2 MiB packs.
- The same `text-tree` mean read amplification rose from about 17x to about
  70x.
- `mixed-tree` compressed bytes barely moved across pack sizes because random
  binary data dominates.
- `dvault-source` improved slightly when treated as one source-like pack, but
  that also means reading one small file decompresses the whole source pack.

Recommendation:

- Default interactive pack target should stay near 512 KiB to 1 MiB.
- Bulk import or compaction may use 2 MiB to 4 MiB packs for source/text-heavy
  archives.
- 8 MiB should be an archival/compaction choice, not the interactive default.

## Grouping Findings

Path order, extension grouping, and simple content-class grouping were usually
very close in this fixture set.

Recommendation:

- Do not add complex grouping heuristics to the normal writer yet.
- Start with path order plus a simple large-file/small-file split.
- Revisit extension/content grouping only after the zstd encoder improves, or
  after a broader real-world corpus proves it matters.

## Metadata Findings

The first v2 columnar metadata estimate was smaller on `dvault-source`, but not
universally smaller. In repeated-small it was worse than the current artifact.
This means the metadata design needs more work before replacing the current
format.

Likely improvements:

- Avoid duplicating extent data between metadata tables and pack manifests.
- Compress metadata frames separately.
- Use a real path trie rather than the probe's simple component table.
- Store optional pack-local recovery name hints only in recovery-heavy profiles.

## Conclusions

1. The clean-slate v2 design is architecturally attractive, but not yet proven
   as a size win.
2. The format should not move to huge solid packs by default. The read
   amplification cost is too high for small random reads.
3. Compression backend quality remains the main size opportunity.
4. A v2 prototype is still worthwhile because it can make updates, checkpoints,
   range planning, and recovery cleaner.
5. The upstream `ruzstd` patch is useful but only a first tiny step.

## Recommended Next Steps

1. Submit the small `ruzstd` raw-fallback patch upstream after human review.
2. Keep current Lockbox format as the production path for now.
3. Build a separate experimental v2 encoder/reader module rather than mutating
   the current page format.
4. Improve the metadata prototype:
   - real path trie
   - compressed metadata frames
   - no duplicated extent tables
5. Run the v2 probe against larger real source trees and package caches.
6. Continue pure-Rust zstd work on higher-impact encoder areas:
   - literal Huffman choice
   - FSE table selection
   - rolling match history/window behavior
   - better match finder for default/better levels
