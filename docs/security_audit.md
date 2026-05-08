# Security Audit

This is a design/code audit snapshot for the current prototype. It is not a
cryptographic review.

## Strengths

- Paths are encrypted metadata and are not stored in cleartext indexes.
- Archive paths are logical paths, not host paths.
- `..`, Windows drive syntax, UNC-like roots, backslashes, controls, dangerous
  Unicode controls, and non-canonical Unicode metadata are rejected.
- Symlink paths and targets use the same logical-path rules.
- Segment bodies are encrypted and authenticated with ChaCha20-Poly1305.
- Password slots use Argon2id with per-slot salts.
- Recipient slots use ML-KEM-1024 wrapping.
- Key directories are capped at 1 MiB.
- Unlock caching stores unwrapped vault keys only in a per-user agent process,
  not on disk.
- Core and agent key buffers zeroize on drop and try to lock memory.

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
- Memory locking is best effort. It can fail due to OS limits; zeroization is
  still the reliable baseline.
- Compression-ratio and decompression-bomb tests need to be strengthened.
- Filesystem extraction needs a platform-specific hardening pass before it is
  treated as production safe.
- Fuzzing is still required for header, key directory, record scanner,
  manifest, payload decoders, path validation, and recovery.
- Fuzz scaffolding now exists under `rust/fuzz`, but corpus collection and CI
  fuzz runs are not yet in place.

## Release Blockers

- Third-party cryptographic review.
- Fuzzing harnesses and corpus.
- Windows/macOS/Linux agent IPC tests in CI.
- Benchmarks for recursive add and full extraction.
- File-backed storage to avoid full-vault memory residency.
