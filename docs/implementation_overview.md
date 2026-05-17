# Implementation Overview

This document keeps implementation and format direction out of the top-level
README. User-facing command examples are in [cli_how_to.md](cli_how_to.md).
Exact on-disk structures are in [file_formats.md](file_formats.md).

## Goals

- Fast range access to individual files.
- Browser-compatible reads over HTTP range requests.
- Private paths and metadata; paths are not stored in cleartext indexes.
- Append-friendly writes with reuse of deleted or replaced page space.
- Checkpointed TOCs for fast open.
- Recovery APIs that can salvage valid files when headers, TOCs, or pages
  are damaged.
- Native and WASM-friendly Rust crates.

## Crate Roles

`lockbox_core` owns the portable `.lbox` format and storage API. It is checked
for Linux, macOS, Windows, Android, iOS, WASI, and browser-style
`wasm32-unknown-unknown` builds.

`lockbox_vault` owns native local-vault behavior, unlock-cache agent transport,
private key storage, trusted recipient storage, and key-directory backups.
Mobile and WASM applications should use platform-specific vault integration
instead of embedding the native agent.

## Format Model

Lockbox v2 uses a small cleartext header plus fixed-size pages. Most page
bodies are encrypted and authenticated. Key-directory pages are cleartext
page-cache pages because unlock metadata must be read before the content key is
available.

```text
[ Header ]
[ Page: commit root, encrypted body ]
[ Page: TOC metadata + file content, encrypted body ]
[ Page: env metadata, encrypted body ]
[ Page: key directory, cleartext checksummed body ]
...
```

Cleartext page headers contain scanner-safe framing only:

```text
magic
page version
sequence
stored body length
SHA-256 public header checksum
```

Paths, file names, file contents, env names, env values, permissions, symlink
targets, and TOC entries are inside fixed-size encrypted pages. Metadata
pages are currently 128 KiB and file-data pages are 8 MiB. Normal storage
writes operate on whole physical pages.

## TOC And Recovery

Normal open uses the header's latest authenticated commit root. The commit root
points at the current TOC root, env root, and persisted free-space index.

Recovery does not trust the fixed header or TOC. It scans fixed-size
pages, verifies checksums, authenticates encrypted pages, and rebuilds the best
available TOC. If the latest TOC is corrupt but file pages are
intact, files can still be recovered. If a file page is corrupt but the
TOC survives, recovery reports that file as partial.

```rust
let report = RecoveryScanner::scan_bytes(bytes, key);
let clean = RecoveryScanner::salvage_bytes(damaged_bytes, key)?;
```

## Page Cache

The core library uses one decoded-page cache for pages read from the lockbox.
TOC nodes, file pages, symlinks, env objects, free-index objects, key
directories, and commit roots share one weighted LRU budget keyed by page
offset. Metadata pages weigh less than file-data pages.

The page cache owns page decoding, encoding, encryption, cleartext page
checksums, flushing, redaction, and zeroing. Correctness does not require the
full TOC or full lockbox to fit in memory.

The default cache limit is `Auto`:

- minimum useful cache: the larger of sixty-four metadata pages or 64 MiB
- target: about 15% of currently available/reclaimable memory
- native cap: 4 GiB unless the caller overrides it
- WASM default: 64 MiB

Embedders can choose a fixed budget or disable caching:

```rust
use lockbox_core::{CacheLimit, Lockbox, LockboxOptions, WorkloadProfile};

let options = LockboxOptions {
    cache_limit: CacheLimit::Bytes(256 * 1024 * 1024),
    workload_profile: WorkloadProfile::Interactive,
    ..LockboxOptions::default()
};
let lockbox = Lockbox::open_with_options(bytes, key, options)?;
```

## Page Reuse And Compaction

Deleted or replaced pages become reusable slots. New pages reuse available
slots when they fit, while metadata updates remain checkpointed and crash-safe.

Deletes and replacements redact old physical pages during commit. If a page
also contains current objects, those objects are relocated first, then the old page
is zeroed so stale ciphertext is not left recoverable through normal recovery.

Compaction is a maintenance operation for heavily fragmented archives. It
logically rewrites the current state into a fresh lockbox through the same
page-cache-backed APIs and swaps the backing storage after the replacement
commits.

## Browser And Web Service Access

The target web flow is:

```text
1. Browser fetches the fixed header range.
2. Browser fetches the latest checkpoint/TOC ranges.
3. User lists a directory.
4. Browser fetches only the TOC pages and file pages needed.
5. WASM decrypts/decompresses selected files locally.
```

The Rust core is intended to grow a range-planning layer so language bindings
can hide these details behind higher-level APIs.

## Compression And Crypto

The current Rust implementation includes:

- ChaCha20-Poly1305 with 256-bit content keys for page-body encryption.
- Argon2id password key derivation for password slots.
- ML-KEM-1024 recipient wrapping for public-key sharing.
- Zstandard page compression through a pure-Rust backend.
- Independent compressed chunks for large files so random access and recovery
  remain practical.

Avoid whole-archive solid compression as the default because it conflicts with
range reads and partial recovery.

## Repository Notes

The existing Dart implementation remains in place while the Rust core is
developed. The intended end state is for Dart and web code to call the Rust
core through FFI/WASM bindings rather than maintaining independent format
logic.
