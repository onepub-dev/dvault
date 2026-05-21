# CDC Dedupe Threat And Recovery Design

Date: 2026-05-21

Status: research gate, not approved for implementation.

## Scope

Content-defined chunking (CDC) is only worth considering if it reduces size on
realistic duplicate or shifted-version corpora while preserving Lockbox's core
properties:

- private paths and metadata
- authenticated encrypted pages
- bounded decompression
- partial file access
- recovery after TOC damage
- delete/redaction semantics for removed files

This document is the prerequisite design gate. A CDC prototype should not land
until the threat model, recovery model, and measurement gates below are
satisfied.

## External References

- [Borg](https://borgbackup.readthedocs.io/en/stable/) uses content-defined
  chunking so inserted or shifted data does not force
  every later chunk boundary to change.
- [Restic](https://github.com/restic/restic/blob/master/doc/design.rst) uses
  Rabin-fingerprint CDC and stores content-addressed blobs in encrypted packs.
  Restic's design notes also call out CDC chunk-size leakage and mitigation
  work.
- [FastCDC](https://www.usenix.org/conference/atc16/technical-sessions/presentation/xia)
  is a useful implementation reference because it targets lower CPU overhead
  than classic byte-by-byte Rabin CDC.
- Recent
  [CDC attack work](https://arxiv.org/abs/2504.02095)
  shows that observable chunk-size sequences and chunker parameters can become
  part of the security model, not just the compression model.

## Threat Model

### Attackers

- Storage reader: can copy the lockbox file and observe its public size,
  update timing, page count, and file growth.
- Storage writer: can truncate, corrupt, replay, or replace lockbox bytes.
- Access-pattern observer: can observe upload/download ranges or local storage
  reads if Lockbox is used over a remote backing store.
- Chosen-input collaborator: can cause known files or near-duplicate files to
  be inserted and later observe lockbox growth.
- Authorized recipient: can decrypt the lockbox after being added and may try
  to recover stale data that should have been deleted before their access.

### Assets

- File contents.
- Logical paths, permissions, symlink targets, and environment variables.
- Equality of private file content.
- Chunk boundaries and chunk sizes.
- Deletion history and stale content.
- Current liveness of chunks referenced by more than one file.

### Leakage Risks

- Same-lockbox equality: dedupe necessarily reveals, to anyone who can decrypt
  metadata, that multiple live files share content chunks.
- Storage-size leakage: even without decrypting metadata, an observer can see
  that a write was smaller because existing chunks were reused.
- Chunk-size leakage: CDC creates data-dependent boundaries. If chunk sizes or
  boundary sequences are externally observable, they may leak information about
  known files or chunker parameters.
- Chosen-input confirmation: an attacker who can insert a known file may infer
  whether related content already existed by measuring growth.
- Stale-data retention: a deleted file must not remain recoverable merely
  because another old manifest or index still points at its chunks.
- Refcount corruption: stale or incorrect refcounts can either leak deleted
  chunks or delete chunks that are still live.

## Required Design Constraints

1. Do not use cross-lockbox or cross-user dedupe.
2. Do not use convergent encryption. Payload encryption must continue using
   normal randomized page encryption.
3. Derive chunk identifiers with a per-lockbox secret, for example a keyed hash
   over plaintext chunk bytes and domain-separated CDC parameters.
4. Treat refcounts as rebuildable cache/index data, not as the source of truth.
5. Keep a path-bearing file manifest for recovery. Chunk records alone are not
   enough to recover filenames or file ordering after TOC loss.
6. Chunk boundaries, chunker parameters, and chunk ids must not be stored in
   clear text.
7. Decompression limits must remain explicit. No CDC chunk or packed group may
   bypass the current decompression-bomb checks.
8. Deletes and recipient changes must continue to redact stale path-bearing
   manifests before the new state is published.

## Candidate Format Shape

This is a design sketch, not a committed format.

### Chunk Records

Each unique chunk is stored as encrypted file-data payload:

- chunk record version
- keyed chunk id
- plaintext chunk length
- compressed length
- compression algorithm
- digest of the compressed bytes
- encrypted compressed chunk bytes

Chunk records do not contain paths. They are recoverable only as content blocks.

### File Manifests

Each live file has an encrypted path-bearing file manifest:

- manifest version
- logical path
- permissions
- total file length
- ordered chunk references
- file offsets and chunk slice lengths
- digest over manifest body

The TOC points to the current file manifest. Recovery scans encrypted pages,
validates file manifests, resolves chunk references, verifies chunks, and
recovers only complete files unless the caller explicitly asks for partial
salvage.

### Indexes

The CDC index maps keyed chunk id to physical chunk record references. It may
be persisted for speed, but it must be rebuildable by scanning current
manifests and chunk records. The authoritative live set is the current TOC plus
valid current file manifests.

### Deletion And Compaction

Deleting or replacing a file redacts its old file manifest through the normal
page-cache write path. Chunk records are reclaimed only after a mark-sweep pass
from current manifests proves that no live manifest references them.

Compaction rebuilds a clean lockbox by copying only current manifests and live
chunks, then regenerating the chunk index. It must not trust stale refcounts in
the old file.

## Recovery Requirements

CDC recovery must pass at least these cases:

- TOC loss with intact manifests and chunks recovers complete files.
- Corrupt manifest produces a partial/corrupt report without trusting its path
  or chunk list.
- Missing chunk referenced by a manifest marks that file partial.
- Corrupt chunk fails digest/authentication before plaintext is returned.
- Duplicate chunk records with the same keyed id are accepted only if the
  verified plaintext identity matches; otherwise recovery reports corruption.
- Deleted file manifests are not recoverable after the delete commit.
- Refcount/index pages may be missing or corrupt and recovery still succeeds by
  scanning manifests/chunks.
- Compaction after deletes removes unreferenced chunks.

## Measurement Plan

Prototype only after this design is accepted. Measure these corpora:

- exact duplicates, to compare against the already rejected exact-file dedupe
  probe
- shifted large files, with insertions near the beginning and middle
- source tree versions across several commits
- maildir or log-like corpora with repeated headers and shifted bodies
- high-entropy files
- mixed fixture with tiny files and incompressible blobs

Metrics:

- final lockbox bytes
- add wall time and max RSS
- chunking CPU separated from compression CPU
- index size and manifest size
- delete/replace commit time
- compaction time after deletes
- single-file and range-read amplification
- recovery time after TOC loss

Decision gate:

- Continue only if realistic shifted/versioned corpora show a large size win
  after index, manifest, and chunk metadata overhead.
- Reject if size gains are limited to synthetic exact duplicates, because zstd
  already handles those well in the current frame model.
- Reject if recovery requires trusting a mutable refcount table.
- Reject if chunk-size or equality leakage cannot be bounded to an explicitly
  accepted archive/backup profile.

## Initial Recommendation

CDC should remain a separate backup/archive-profile project. It is not a
drop-in replacement for the current compression-frame format. The first
prototype should be a measurement harness using the candidate manifest/chunk
shape above, not production read/write support.
