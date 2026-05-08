# Lockbox

Lockbox is an encrypted archive format and library for storing many files in a
single `.lbox` container while still supporting fast access to individual files.

The current direction is a Rust core implementation that can be used from CLI,
Dart, JavaScript/WASM, and other languages through thin bindings.

> Status: the Rust implementation under `rust/lockbox_core` is an early format
> prototype. It exercises the public API, manifest/checkpoint model, path
> privacy, free-space reuse, and recovery behavior. The current in-repo cipher is
> deliberately dependency-free for testability in this environment and must be
> replaced with production AEAD crypto before release.

## Goals

- Fast range access to individual files.
- Browser-compatible reads over HTTP range requests.
- Private paths and metadata; paths are not stored in cleartext indexes.
- Append-friendly writes with automatic reuse of deleted/replaced record space.
- Checkpointed manifests for fast open.
- Recovery APIs that can salvage valid files when headers, manifests, or records
  are damaged.
- Production compression and encryption through Rust crates suitable for native
  and WASM builds.

## Format Model

Lockbox v2 uses a small cleartext frame plus encrypted private payloads.

```text
[ Header ]
[ Record: file metadata + content, encrypted payload ]
[ Record: delete/tombstone, encrypted payload ]
[ Record: manifest checkpoint, encrypted payload ]
...
```

Cleartext record headers contain only scanner-safe framing:

```text
magic
record type
sequence
payload length
record length
payload checksum
header checksum
```

Paths, file names, content, lengths-by-path, and manifest entries are inside the
encrypted payload. This keeps the backing store and web service from seeing
directory structure or file names.

## Manifest And Recovery

Normal open uses the header's latest manifest checkpoint. The manifest is the
current filesystem view: path lookup, file metadata, and physical record
locations.

Recovery does not trust the header or manifest. It scans record frames, verifies
payloads, decrypts metadata, and rebuilds the best available manifest. If the
latest manifest is corrupt but file records are intact, files are still
recoverable. If a file record is corrupt but the manifest survives, recovery
reports that file as partial.

The high-level recovery API is intentionally simple:

```rust
let report = Lockbox::recover(bytes, key);
let clean = Lockbox::salvage(damaged_bytes, key)?;
```

## Rust API

The normal API is intentionally filesystem-like:

```rust
use lockbox_core::Lockbox;

let key = b"correct horse battery staple";
let mut lockbox = Lockbox::create(key);

lockbox.put_file("/docs/a.txt", b"alpha")?;
lockbox.put_file("/docs/b.txt", b"bravo")?;

let bytes = lockbox.get_file("/docs/a.txt")?;
let slice = lockbox.read_file_range("/docs/b.txt", 1, 3)?;
let files = lockbox.list("/docs")?;

lockbox.rename("/docs/b.txt", "/docs/c.txt")?;
lockbox.delete("/docs/a.txt")?;
lockbox.commit()?;

let stored_bytes = lockbox.to_bytes();
let reopened = Lockbox::open(stored_bytes, key)?;
```

Current tested APIs:

- `create`
- `open`
- `to_bytes`
- `put_file`
- `put_file_with_permissions`
- `put_symlink`
- `get_file`
- `get_symlink_target`
- `read_file_range`
- `list_iter`
- `list`
- `list_glob`
- `ListOptions`
- `stat`
- `permissions`
- `is_symlink`
- `set_env`
- `get_env`
- `remove_env`
- `list_env`
- `get_all_env`
- `delete`
- `rename`
- `commit`
- `extract_all`
- `extract_all_nodes`
- `recover`
- `salvage`

## Segment Reuse

Lockbox should not rely on compaction as the normal way to manage archive
growth. Deleted or replaced records become reusable slots. New records reuse
available slots when they fit, while metadata updates remain checkpointed and
crash-safe.

Compaction should remain a maintenance operation for heavily fragmented
archives, not the default write path.

## Security Posture

Lockbox should be safe by default when opening or expanding an untrusted
archive. The format and APIs are designed to avoid common archive attack classes
seen in ZIP, TAR, RAR, 7-Zip, and similar tools.

Default rules:

- Paths are private metadata and are never stored in cleartext indexes.
- Lockbox paths are logical archive paths, not host filesystem paths.
- `..` path components are banned completely. Finding one during parsing,
  listing, extraction, recovery, or symlink validation is treated as tampering.
- Windows drive paths and alternate data stream syntax are banned by rejecting
  `:` in archive paths.
- UNC-like paths are banned by rejecting `//` roots and backslash separators.
- NUL bytes, ASCII control characters, empty path components, `.`, duplicate
  separators, overlong paths, and excessive path depth are rejected.
- Unicode paths are supported and canonicalized to NFC at API boundaries.
- Stored metadata must already be canonical NFC; non-canonical paths found while
  decoding archive metadata are rejected as tampering.
- Unicode bidirectional controls, C1 controls, zero-width/invisible formatting
  characters, soft hyphen, variation selectors, and other selected
  default-ignorable controls are rejected by default to reduce visual spoofing.
- Path limits are enforced in UTF-8 bytes, component bytes, and component depth.
- Only regular file payloads are materialized by default.
- Symlinks are not extracted by default. Future symlink metadata must pass the
  same logical-path validation for both link path and target.
- Bulk extraction is bounded by default with maximum file count, per-file bytes,
  and total expanded bytes.
- Existing destination files must not be overwritten by default when filesystem
  extraction is added.
- Compression must be per-file or per-chunk, never whole-archive solid
  compression by default.
- Decompression must be streaming and bounded by authenticated uncompressed
  lengths, total output limits, and compression-ratio limits once compression is
  implemented.
- Nested archives are never expanded automatically.

The Rust prototype currently enforces strict logical and Unicode path
validation, symlink-path validation, private path/content storage, parser
rejection of tampered paths in encrypted metadata, and bounded in-memory
`extract_all`.
Production work still needs real AEAD associated-data checks, zstd ratio-limit
tests, filesystem extraction hardening, and fuzzing.

## Browser And Web Service Access

The target web flow is:

```text
1. Browser fetches the fixed header range.
2. Browser fetches the latest checkpoint/manifest ranges.
3. User lists a directory.
4. Browser fetches only the manifest pages and file records needed.
5. WASM decrypts/decompresses selected files locally.
```

The Rust core will grow a `RangeFetcher`/range-planning layer so language
bindings can hide these details behind:

```rust
remote.get_file("/docs/a.txt").await?
remote.list("/docs").await?
```

## Compression And Crypto Roadmap

Production Lockbox should use:

- XChaCha20-Poly1305 or another modern AEAD for record/chunk encryption.
- Argon2id or a caller-supplied raw key for key derivation.
- Zstandard as the default compression engine.
- Independent compressed chunks for large files so random access and corruption
  recovery remain practical.

Avoid whole-archive solid compression as the default because it conflicts with
range reads and partial recovery.

## Development

Run the Rust tests:

```bash
cd rust/lockbox_core
cargo test
```

The Rust suite currently has 46 tests covering:

- create/open/commit round trips,
- put/get/range/list/stat behavior,
- iterator-first listing with Rust-side filtering,
- declarative glob filtering for binding-friendly callers,
- list options for node type filtering and limits,
- encrypted environment variable records with lazy loading,
- env set/get/remove/list/get-all behavior,
- env name/value validation and privacy smoke tests,
- invalid path rejection,
- Windows drive, UNC, backslash, NUL, control character, `.` and `..`
  rejection,
- path length and path depth limits,
- Unicode path round trips,
- NFC canonicalization for storage and lookup,
- Unicode normalization collision handling,
- bidi, C1, zero-width, and variation-selector rejection,
- bounded extraction limits for file count, per-file bytes, and total bytes,
- empty files, larger files, and many-file archives,
- range reads past file boundaries,
- non-recursive directory listing,
- symlink round trips with safe extraction skipping symlinks by default,
- opt-in symlink extraction through extraction policy,
- permission metadata preservation and invalid permission rejection,
- delete, rename, and replacement,
- deleted record space reuse,
- path/content privacy smoke tests,
- tampered encrypted metadata path rejection,
- corrupt header recovery,
- missing manifest pointer recovery,
- corrupt manifest recovery,
- corrupt file record partial recovery,
- corrupt frame-header accounting,
- truncated-tail recovery,
- deleted files staying deleted during manifest rebuild,
- salvage to a clean lockbox,
- salvage omitting corrupt file records,
- wrong-key failure.

Missing before production: property/fuzz tests, real AEAD test vectors, zstd
compression tests, range-fetch tests, crash-consistency tests, and FFI/WASM
binding tests.

## Repository Notes

The existing Dart implementation remains in place while the Rust core is
developed. The intended end state is for Dart and web code to call the Rust core
through FFI/WASM bindings rather than maintaining independent format logic.

## License

MIT License - see [LICENSE](LICENSE).
