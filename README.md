# Lockbox

Lockbox is an encrypted archive format and library for storing many files in a
single `.lbox` container while still supporting fast access to individual files.

Terminology is explicit:

- A **lockbox** is the portable `.lbox` container file that stores compressed
  and encrypted data.
- A **vault** is the user's local private store on their own computer. It may
  contain the user's private key, trusted keys, local key-directory backups, and
  other user-local state.

See [docs/terminology.md](docs/terminology.md) for the canonical definitions.

The current direction is a Rust core implementation that can be used from CLI,
Dart, JavaScript/WASM, and other languages through thin bindings. Native
desktop/server tools can also use `lockbox_vault` for the local unlock-cache
agent and high-level vault API.

The `lockbox_core` crate is checked for Linux, macOS, Windows, Android,
iOS, WASI, and browser-style `wasm32-unknown-unknown` builds. The
`lockbox_vault` crate contains the native unlock-cache agent transport and is
intended for desktop/server CLIs and bindings. Mobile and WASM applications
should embed the core crate through platform bindings and provide their own
platform vault integration.

> Status: the Rust implementation under `rust/lockbox_core` is the production
> direction for the first Lockbox format release. The format is still pre-1.0,
> so breaking changes are allowed while the design is finalized, but code added
> here should be treated as the intended implementation. we  bodies are
> compressed with zstd, encrypted with ChaCha20-Poly1305, and lockbox content
> keys can be derived with Argon2id or wrapped with ML-KEM-1024. Third-party
> cryptographic review is still a release blocker.

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

Lockbox v2 uses a small cleartext page frame plus encrypted private page bodies.
Key-directory pages are clear-text page-cache pages because unlock metadata must
be readable before the content key is available.

```text
[ Header ]
[ Page: file metadata + content, encrypted body ]
[ Page: delete/tombstone, encrypted body ]
[ Page: manifest checkpoint, encrypted body ]
...
```

Cleartext page headers contain only scanner-safe framing:

```text
magic
page version
sequence
stored body length
SHA-256 public header checksum
```

Paths, file names, content, lengths-by-path, and manifest entries are inside
fixed-size encrypted pages. Metadata pages are currently 128 KiB and file-data
pages are 8 MiB. Normal storage writes operate on whole physical pages. This
hides the true size of tiny files, env vars, symlinks, and metadata from the
backing store and from a range-request based web service.
Clear-text pages use page-format checksums validated by the page cache.

## Manifest And Recovery

Normal open uses the header's latest manifest checkpoint. The manifest is the
current filesystem view: path lookup, file metadata, and physical record
locations.

Recovery does not trust the header or manifest. It scans fixed-size pages,
verifies payloads, decrypts metadata, and rebuilds the best available
manifest. If the latest manifest is corrupt but file pages are intact, files are
still
recoverable. If a file record is corrupt but the manifest survives, recovery
reports that file as partial.

The high-level recovery API is intentionally simple:

```rust
let report = Lockbox::recover(bytes, key);
let clean = Lockbox::salvage(damaged_bytes, key)?;
```

## Key Management

Normal lockboxes use a random content key. Users unlock that content key through
one or more key slots stored in clear-text key-directory pages. The header
points at the current primary key-directory page, and the directory payload is
capped at 1 MiB to avoid unbounded metadata processing.
Because key-directory pages are clear-text page-cache pages, password and
recipient unlock read the current key-directory page through the page-cache
read/decode boundary. Raw byte scanning is only a recovery fallback for damaged
headers or missing roots.

Each lockbox also has a public random UUID in the header. The CLI uses that UUID
to identify per-user unlock-cache entries and local vault records without
relying on file paths.

Supported slots are password slots and ML-KEM-1024 recipient slots. Opening does
not require labels: the library tries each matching slot type until one unwraps
and authenticates the content key.

```rust
let mut lockbox = Lockbox::create_with_password(b"shared password")?;
let slot_id = lockbox.add_recipient_key(&recipient_public_key)?;
lockbox.remove_key_slot_and_compact(slot_id)?;

let lockbox = Lockbox::open_with_password(bytes, b"shared password")?;
let lockbox = Lockbox::open_with_recipient(bytes, &my_private_key)?;
```

Removing a key slot is intentionally conservative: the library rewrites and
compacts the live lockbox state so old key-directory history is not left as an
easy recovery path for the removed credential.

The CLI direction is sudo-like:

```bash
lockbox open secrets.lbox
lockbox list secrets.lbox
lockbox lock secrets.lbox
```

`open` unwraps the content key and stores it in a per-user in-memory agent with a
sliding TTL. Normal commands ask the agent for the unwrapped content key by
lockbox UUID. No password, private-key passphrase, bearer token, or content key
is written to a cache file.

See [docs/key_management.md](docs/key_management.md) for design intent and CLI
direction. See [docs/format.md](docs/format.md) for the current header,
key-directory, and fixed page layout.

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

Native CLIs should use the higher-level vault crate instead of talking to the
agent protocol directly:

```rust
use lockbox_vault::{local_vault, SecretString};

let vault = local_vault();
let password = SecretString::from_bytes(b"pw".to_vec());
vault.create_lockbox_with_password("secrets.lbox", &password)?;
vault.unlock_lockbox_with_password("secrets.lbox", &password)?;

let mut lockbox = vault.open_lockbox("secrets.lbox")?;
lockbox.add_file("notes.txt", "/notes.txt")?;
lockbox.commit()?;

vault.lock_lockbox("secrets.lbox")?;
```

`lockbox_vault::VaultDirectory` provides the local persistent vault store for
native tools. It stores private recipient keys, trusted recipient public keys,
and local key-directory backups separately from the portable `.lbox` file.

Current tested APIs:

- `create`
- `open`
- `create_with_password`
- `open_with_password`
- `unlock_with_password`
- `create_with_recipient`
- `open_with_recipient`
- `unlock_with_recipient`
- `add_password_slot`
- `add_recipient`
- `add_recipient_key`
- `change_password`
- `remove_key_slot`
- `remove_key_slot_and_compact`
- `list_key_slots`
- `to_bytes`
- `put_file`
- `put_file_with_permissions`
- `open_path`
- `write_to_path`
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
- `extract_to_directory`
- `recover`
- `salvage`

Environment variables are encrypted metadata, not file entries. They do not
appear in directory listings and should be loaded only when `get_env`,
`list_env`, or `get_all_env` is called. The format stores env vars in a
commit-root-referenced live env BTree with packed env leaf pages and routing-only
internal pages. Env updates and deletes sanitize old env tree pages during
commit; an append-only env history is not acceptable because newly added
recipients could decrypt stale secrets.

Symlinks are live TOC entries that point at encrypted symlink metadata objects.
The TOC stores the link path, node kind, and object reference; the symlink
target lives in the referenced metadata object. Many symlink objects are packed
into shared metadata pages so symlinks remain recoverable without paying one
page per link.

### Page Cache

The core library uses a unified decoded-page cache for pages read from the
lockbox. TOC nodes, file pages, symlinks, env objects, free-index objects, key
directories, and commit roots share one weighted LRU budget keyed by page
offset. Metadata pages weigh less than file-data pages. The cache owns page
encoding, encryption or clear-text checksum policy, flushing, redaction, and
zeroing. Correctness does not require the full TOC or full lockbox to fit in
memory.

The default cache limit is `Auto`. On native platforms this uses a
page-aware minimum and a best-effort memory-pressure target:

- minimum useful cache: the larger of sixty-four metadata pages or 64 MiB
- target: about 15% of currently available/reclaimable memory
- native cap: 4 GiB unless the caller overrides it
- WASM default: 64 MiB, because reliable free-memory information is not
  generally available in browser runtimes

Embedders can choose a fixed budget or disable caching:

```rust
use lockbox_core::{CacheLimit, Lockbox, LockboxOptions, WorkloadProfile};

let options = LockboxOptions {
    cache_limit: CacheLimit::Bytes(256 * 1024 * 1024),
    workload_profile: WorkloadProfile::Interactive,
    ..LockboxOptions::default()
};
let lockbox = Lockbox::open_with_options(bytes, key, options)?;

lockbox.set_cache_limit(CacheLimit::Auto);
lockbox.trim_cache_to(64 * 1024 * 1024);
let stats = lockbox.cache_stats();
```

Workload policy is explicit. The page cache does not guess that a page is
insert-only. CLI-created initial imports use `BulkImport`, which lets file-data
pages flush and drop from cache as they are appended. Metadata and update
workloads keep the default `Interactive` behavior.

## Page Reuse

Lockbox should not rely on compaction as the normal way to manage archive
growth. Deleted or replaced pages become reusable slots. New pages reuse
available slots when they fit, while metadata updates remain checkpointed and
crash-safe.

Deletes and replacements redact old physical pages during commit. If a page also
contains live objects, those objects are relocated first, then the old page is
zeroed so stale ciphertext is not left recoverable through COW history.

Compaction should remain a maintenance operation for heavily fragmented
archives, not the default write path. It is implemented as a logical rewrite:
the live lockbox state is copied into a fresh lockbox through the normal
page-cache-backed APIs and the backing storage is swapped after the replacement
commits. It does not shuffle physical pages inside the old file.

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
- Symlinks are not extracted by default. Symlink metadata must pass the same
  logical-path validation for both link path and target.
- Bulk extraction is bounded by default with maximum file count, per-file bytes,
  and total expanded bytes.
- Existing destination files must not be overwritten by default when filesystem
  extraction is added.
- Compression must be per-file or per-chunk, never whole-archive solid
  compression by default.
- Decompression must be bounded by authenticated uncompressed lengths, total
  output limits, and compression-ratio limits.
- Nested archives are never expanded automatically.

The Rust implementation currently enforces strict logical and Unicode path
validation, symlink-path validation, private path/content storage, parser
rejection of tampered paths in encrypted metadata, fixed-size encrypted pages,
random AEAD nonces for encrypted pages, zstd page compression,
Argon2id password KDF, ML-KEM-1024 key wrapping, and bounded in-memory
`extract_all`.
Production work still needs published crypto test vectors, stronger zstd
ratio-limit tests,
filesystem extraction hardening, and fuzzing.

Current review notes:

- [Performance review](docs/performance_review.md)
- [Security audit](docs/security_audit.md)
- [Rust idioms review](docs/rust_idioms_review.md)
- [Fuzzing](docs/fuzzing.md)
- [CI secret storage comparison](docs/ci_secret_storage_comparison.md)

## Browser And Web Service Access

The target web flow is:

```text
1. Browser fetches the fixed header range.
2. Browser fetches the latest checkpoint/manifest ranges.
3. User lists a directory.
4. Browser fetches only the manifest pages and file pages needed.
5. WASM decrypts/decompresses selected files locally.
```

The Rust core will grow a `RangeFetcher`/range-planning layer so language
bindings can hide these details behind:

```rust
remote.get_file("/docs/a.txt").await?
remote.list("/docs").await?
```

## Compression And Crypto

The Rust implementation now includes:

- ChaCha20-Poly1305 or XChaCha20-Poly1305 with 256-bit content keys for
  page-body encryption. The current code uses ChaCha20-Poly1305.
- Argon2id password key derivation, or a caller-supplied raw content key.
- NIST ML-KEM-1024/FIPS 203 for post-quantum public-key wrapping when content
  keys need to be shared or stored for recipients.
- Zstandard as the default page compression engine.
- The core uses a pure-Rust zstd backend so embedders do not need a C zstd
  toolchain on desktop, mobile, or WASM targets.
- Independent compressed chunks for large files so random access and corruption
  recovery remain practical.

Avoid whole-archive solid compression as the default because it conflicts with
range reads and partial recovery.

Symmetric encryption is the only content-encryption layer currently implemented.
For quantum resistance this requires high-entropy 256-bit content keys; human
passwords must go through a memory-hard KDF before they wrap content keys.

## Key Sharing Model

The intended sharing model is deliberately narrow:

- Each lockbox has one random 256-bit content key used for content encryption.
- The content key can be unlocked from a password slot.
- The same content key can also be unlocked from a public-key recipient slot.
- Public-key sharing uses the recipient's long-lived public key; the recipient
  keeps the matching private key.
- The normal user does not need a different public/private keypair per lockbox.

In other words, a shared lockbox can support both:

```text
password -> Argon2id -> unwrap content key
recipient private key -> ML-KEM-1024 decapsulation -> unwrap content key
```

This lets a lockbox be shared by password when that is the simplest operational
choice, or by public key when the recipient should not know or reuse a password.
The key-slot metadata should stay minimal: slot id, slot type, algorithm, and
the data required to unwrap the content key. Human-readable labels are not part of
the default model because they can leak information.

See [Key Management Design](docs/key_management.md) for the detailed design
intent, use cases, and target CLI shape.

## Development

Run the Rust tests:

```bash
cd rust/lockbox_core
cargo test
```

Check the supported portable core targets:

```bash
cd rust
cargo check -p lockbox_core --target aarch64-linux-android
cargo check -p lockbox_core --target aarch64-apple-ios
cargo check -p lockbox_core --target wasm32-unknown-unknown
cargo check -p lockbox_core --target wasm32-wasip2
```

The Rust workspace suite currently has over 100 tests covering:

- create/open/commit round trips,
- put/get/range/list/stat behavior,
- iterator-first listing with Rust-side filtering,
- declarative glob filtering for binding-friendly callers,
- list options for node type filtering and limits,
- encrypted environment variable pages with lazy loading,
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
- deleted page space reuse,
- path/content privacy smoke tests,
- tampered encrypted metadata path rejection,
- corrupt header recovery,
- missing manifest pointer recovery,
- corrupt manifest recovery,
- corrupt file page partial recovery,
- corrupt page accounting,
- truncated-tail recovery,
- deleted files staying deleted during manifest rebuild,
- salvage to a clean lockbox,
- salvage omitting corrupt file records,
- wrong-key failure.

Missing before production: published AEAD/KDF/KEM test vectors, range-fetch
tests, broader fuzz corpora, and FFI/WASM binding tests.

## Repository Notes

The existing Dart implementation remains in place while the Rust core is
developed. The intended end state is for Dart and web code to call the Rust core
through FFI/WASM bindings rather than maintaining independent format logic.

## License

MIT License - see [LICENSE](LICENSE).
