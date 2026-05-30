# Lockbox Archive V2 Restructure Proposal

This note explores a clean-slate archive layout for better compression,
single-thread write speed, range reads, partial updates, and damage recovery.
It intentionally ignores compatibility with the current pre-1.0 physical
format, while preserving the product goals documented in `file_formats.md`.

## Goals

- Improve compression ratio for source trees and many-small-file archives.
- Keep random reads practical without decompressing the whole archive.
- Preserve crash recovery and partial salvage after truncated or corrupt data.
- Support append-style updates and later compaction.
- Keep paths, metadata, and recovery manifests encrypted.
- Keep the default writer single-thread friendly before adding parallelism.
- Avoid compression FFI unless pure-Rust options are exhausted.

## Non-Goals

- Byte compatibility with current pages, TOC nodes, or compression-frame
  manifests.
- Whole-archive solid compression as the default.
- Default content-defined dedupe in the interactive write path.
- Exposing many user-facing compression knobs.

## Core Hypothesis

The current format has moved toward compressed file frames, but it still pays
page/TOC/manifest overheads that are awkward for high-ratio archive workloads.
A cleaner append-only segment format can improve both compression and speed by
making compression packs the primary physical unit, then layering compact
indexes over those packs.

The proposed layout is:

```text
header
segment 0
  pack frames
  metadata delta frames
  checkpoint frame
segment 1
  pack frames
  metadata delta frames
  checkpoint frame
...
footer mirror / latest checkpoint pointer
```

Every frame is independently authenticated and length-delimited. Checkpoints
make the latest logical state cheap to open, while older intact frames remain
salvageable.

## Physical Frame

Each physical frame uses a small binary header followed by an encrypted payload:

```text
frame_header {
  magic_or_sync: fixed bytes
  version: varint
  frame_kind: varint
  flags: varint
  logical_id_delta: varint
  plaintext_len: varint
  ciphertext_len: varint
  previous_frame_distance: optional varint
  header_crc: u32
}
payload {
  aead_nonce
  ciphertext
  auth_tag
}
```

The encrypted plaintext starts with a schema-specific payload header. This keeps
public scanning possible without exposing paths or metadata.

Frame kinds:

- `pack`: compressed file bytes plus a compact internal pack manifest.
- `metadata_delta`: path table, file table, directory table, tombstones, and
  attribute deltas.
- `dictionary`: optional compression dictionary material.
- `checkpoint`: root pointers, generation, and index summaries.
- `redaction`: overwrite proof or tombstone for physical ranges redacted during
  compaction.

## Pack Frames

Pack frames become the main storage unit. A pack is independently compressed and
independently recoverable.

Small files:

- Group by similarity class before compression.
- Candidate grouping keys: extension, MIME guess, executable/text/binary,
  basename patterns, and small content samples.
- Target uncompressed pack size: 1 MiB interactive, 4-8 MiB bulk import.
- Store many complete small files in one pack.

Large files:

- Split into large extents, probably 4-16 MiB by default.
- Each extent is independently compressed.
- The file table maps logical file ranges to pack extents.
- Updates rewrite only changed extents, not the whole file.

The internal pack manifest stores:

```text
pack_manifest {
  pack_id_delta
  compression_algorithm
  compression_profile
  uncompressed_len
  compressed_len
  content_digest
  slice_count
  slices[]
}

slice {
  file_id_delta
  file_offset_delta
  pack_offset_delta
  len
  flags
}
```

Unlike the current recovery manifest, pack slices should use numeric `file_id`
references, not repeated paths. Recovery can recover orphaned file IDs first,
then attach names from the latest intact metadata checkpoint. When metadata is
lost, pack-local optional name hints can be enabled for recovery-heavy profiles,
but the default should avoid path repetition in every pack.

## Metadata Layout

Metadata should be columnar and delta-coded rather than row-oriented.

Tables:

- `path_components`: interned path components sorted lexicographically.
- `path_trie`: parent/component/kind rows with delta-coded IDs.
- `files`: file ID, path ID, size, mtime, mode ref, extent-list ref.
- `extents`: file ID deltas, file offset deltas, pack ID deltas, pack offsets,
  lengths, and digest refs.
- `attrs`: rare metadata such as xattrs, symlinks, platform flags, and owners.
- `tombstones`: deleted path/file IDs by generation.

Path compression:

- Store paths as a trie, not repeated full strings.
- Sort sibling components and delta-code component IDs.
- Use suffix sharing only for component strings where it beats simple
  interning.
- Keep a small static dictionary for common names such as `src`, `lib`, `test`,
  `README`, `Cargo.toml`, and package-lock style paths only if benchmarks prove
  it is worthwhile.

Numeric compression:

- Use unsigned varints.
- Delta-code sorted IDs and offsets.
- Use zigzag varints only where negative deltas are expected.
- Store booleans and small enums in bitsets where table density is high.

## Checkpoints

A checkpoint is the authoritative logical root for a generation:

```text
checkpoint {
  generation
  previous_checkpoint_frame
  metadata_delta_chain_root
  live_pack_index_root
  deleted_physical_ranges_root
  key_directory_root
  archive_summary
}
```

The header and footer should contain mirrored pointers to recent checkpoints,
but recovery must not require either to be intact. A scanner can find checkpoint
frames by frame headers and validate them independently.

## Update Model

Normal updates are append-only:

1. Write new pack frames for changed file bytes.
2. Write metadata deltas for path/table/extent changes.
3. Write a checkpoint frame.
4. Optionally redact superseded physical ranges according to the security
   policy.

Compaction writes a replacement archive from the latest checkpoint and live
packs. It may choose larger packs and higher-ratio compression profiles.

## Recovery Model

Recovery should work in tiers:

1. Open latest valid checkpoint from mirrored pointers.
2. If that fails, scan for checkpoint frames and use the highest valid
   generation.
3. If checkpoints are missing, scan pack frames and recover file IDs/extents.
4. If metadata is partial, emit recovered file IDs with best-effort names from
   any intact metadata deltas or optional pack-local hints.

Each pack frame validates independently:

- frame header CRC
- AEAD authentication
- compressed payload digest or AEAD-associated digest
- decompressed length limit
- pack manifest slice bounds

## Expected Wins

- Less path repetition in recovery metadata.
- Better small-file compression from larger similarity packs.
- Faster writes by producing fewer metadata/page objects.
- Faster opens from checkpoint summaries.
- Cleaner range planning because extents directly reference pack frames.
- Simpler compaction because live state is checkpoint plus pack reachability.

## Expected Costs

- More complex recovery when metadata is lost because packs reference file IDs
  rather than full paths.
- Updates to small files inside solid packs rewrite whole packs.
- Redaction is harder if obsolete encrypted bytes share physical frames with
  live bytes; pack-level grouping must account for the security policy.
- More migration work from the current page-oriented implementation.

## Experiments

The prototype should measure each hypothesis independently:

1. `columnar-metadata`: current TOC/manifest versus v2 columnar metadata only.
2. `small-pack-size`: 512 KiB, 1 MiB, 2 MiB, 4 MiB, and 8 MiB small-file packs.
3. `grouping-key`: path order versus extension grouping versus sampled content
   grouping.
4. `large-extent-size`: 1 MiB, 2 MiB, 4 MiB, 8 MiB, and 16 MiB extents.
5. `pack-name-hints`: no hints versus compact path hints for recovery.
6. `checkpoint-frequency`: every commit versus every N MiB for bulk import.
7. `offline-dedupe`: optional compaction-only CDC/dedupe versus no dedupe.

Benchmarks should report:

- archive bytes
- metadata bytes
- compressed data bytes
- add/import wall time
- extract full tree wall time
- extract single small file
- extract 4 KiB range from a large file
- peak RSS
- recovery scan time
- recovered intact/partial files after truncation and random frame corruption

Baselines:

- current Lockbox format
- current Lockbox with any accepted compression improvements
- `tar.zst` at comparable compression levels
- `gpg` over tar or comparable encrypted archive baseline

## Recommendation

Prototype this as a separate experimental encoder/decoder rather than mutating
the current format in place. The first milestone should ignore encryption and
redaction and prove the storage model:

1. pack builder
2. columnar metadata encoder
3. checkpoint writer/reader
4. range planner
5. benchmark harness

The second milestone should add encryption, authenticated frame headers, and
recovery scanning. Only after those results should the current page-based format
be replaced or migrated.
