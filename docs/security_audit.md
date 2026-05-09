# Security Audit

This is a design/code audit snapshot for the current pre-1.0 implementation. It is not a
cryptographic review.

## Strengths

- Paths are encrypted metadata and are not stored in cleartext indexes.
- Archive paths are logical paths, not host paths.
- `..`, Windows drive syntax, UNC-like roots, backslashes, controls, dangerous
  Unicode controls, and non-canonical Unicode metadata are rejected.
- Symlink paths and targets use the same logical-path rules.
- Fixed-size segment pages are encrypted and authenticated with
  ChaCha20-Poly1305. Each page stores a unique nonce in the page header and
  authenticates page identity through AEAD AAD.
- Password slots use Argon2id with per-slot salts.
- Recipient slots use ML-KEM-1024 wrapping.
- Key directories are capped at 1 MiB.
- Unlock caching stores unwrapped vault keys only in a per-user agent process,
  not on disk.
- Core and agent key buffers zeroize on drop and try to lock memory.
- TOC decode rejects unsorted or duplicate leaf paths, unsorted or duplicate
  internal separators, invalid child offsets, and invalid stored paths before
  extraction trusts TOC metadata.
- Current commits now publish an authenticated commit-root object inside a
  fixed-size encrypted segment page. The commit root points at the live TOC root
  and the persisted free-space index.
- The committed TOC is live-only; deletes are represented in recovery history,
  not as tombstones in the current namespace.

## Risks And Required Follow-Up

- The Windows named-pipe transport must be compiled and tested on Windows. SID
  validation, explicit pipe DACLs, and pipe lifecycle behavior are the
  highest-risk platform-specific code.
- Unix agent peer-credential validation is not yet implemented. The private
  directory is useful, but peer credential checks should be added where
  available.
- The agent protocol is still plaintext over local IPC. That is acceptable for a
  same-user local channel, but request limits and parser tests must continue to
  expand.
- `LOCKBOX_PASSWORD` is useful for tests but should remain hidden in verbose
  help only and should be discouraged for real use.
- The core still exposes raw-key APIs for developer/testing use. Normal bindings
  should guide callers toward password/recipient unlock APIs.
- The live storage path now uses fixed-size encrypted segment pages. Format
  review should treat `docs/format.md` as the current contract and continue to
  audit that all normal reads and writes pass through the segment cache.
- Memory locking is best effort. It can fail due to OS limits; zeroization is
  still the reliable baseline.
- Compression-ratio and decompression-bomb tests cover the core segment body
  decoder and extraction limits; they should continue expanding with fuzz
  corpus cases.
- Filesystem extraction needs a platform-specific hardening pass before it is
  treated as production safe.
- Trusted extraction iterators skip redundant path validation only after TOC
  metadata has already been authenticated and validated. Any future recovery or
  partial-scan path must continue using validating decoders.
- Fuzzing is still required for header, key directory, page scanner,
  manifest, payload decoders, path validation, and recovery.
- Fuzz scaffolding exists under `rust/fuzz`, and CI runs a short fuzz smoke
  pass. Corpus collection and longer scheduled fuzz runs are still needed.

## Release Blockers

- Third-party cryptographic review.
- Continue auditing that all normal storage reads and writes pass through the
  segment cache.
- Extend fuzz corpus coverage for multi-page free-space indexes.
- Fuzzing harnesses and corpus.
- Windows/macOS/Linux agent IPC tests in CI, including explicit Windows DACL
  validation.
- Larger recurring benchmarks for 100k+ files, GB-class vaults, and repeated
  append/delete/rename workloads in CI.
