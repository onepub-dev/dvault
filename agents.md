# DVault Design Specification

## Overview
DVault is a secure, encrypted file vault format designed for:
1.  **Streaming**: Ability to read individual files or parts of files without downloading the entire vault.
2.  **Random Access**: Efficiently seek to any byte in any file.
3.  **Small File Efficiency**: Efficient storage of many small files.
4.  **Browser Compatibility**: Designed to work with a Dart Virtual File System backed by SQLite in the browser.

## Requirements

### 0. Page Cache Ownership
All lockbox page reads and writes must go through the page cache, including
secure env pages. The page cache owns page encoding, encryption policy, dirty
tracking, flushing, COW replacement, zeroing of superseded physical pages, and
publication of freed ranges for reuse. Higher-level code must not write storage
directly to append, replace, redact, or update pages.

Allowed exceptions:
-   **Fixed header access**: the lockbox header is fixed at offset `0` and may
    be read directly before roots are known. It may also be written directly as
    the final commit publication step.
-   **Recovery reads**: recovery may scan a damaged lockbox by reading storage
    directly because page-cache indexes and roots may be corrupt or missing.
    When recovery creates the repaired lockbox, it must use the same normal
    lockbox creation and page-cache write APIs used outside recovery.

Unlock is not a page-cache exception. The key directory is a clear-text page
class, so password and recipient unlock should read key-directory pages through
the page-cache page read/decode boundary. Only fallback scans for damaged or
missing roots should inspect raw storage bytes directly.

Compaction is not a page-cache exception and must not move physical pages
in-place. Compact by reading the live logical state, creating a replacement
lockbox through the normal creation APIs, writing all live objects through the
page cache, committing it, and then swapping the backing file or in-memory
storage as a whole.

Metadata such as TOC nodes, environment pages, symlink metadata pages, free
indexes, commit roots, and key-directory pages are page-cache-managed data.
Some page classes may be marked as **clear-text** so they can be read before
the content key is available, or for other format-level purposes. Clear-text
pages are still page-cache-managed pages: callers must write them through the
page-cache page-writing APIs. The page cache/page format layer owns the
clear-text page policy and must add and validate a checksum when writing and
reading clear-text pages.

Encrypted pages use AEAD authentication for body integrity. The page format may
also keep a public page-header checksum as an early corruption filter, but
higher-level code must not add independent checksums for encrypted page
payloads. Clear-text page payloads rely on the page-cache/page-format checksum;
clear-text object formats such as the key directory should not implement their
own nested payload checksums.

### 0.1 Password Ownership
Passwords must be owned and passed as `SecretString`. Public Rust APIs must not
accept or store password byte slices, `Vec<u8>`, or `String` values as password
state. Temporary borrowed views may be produced only at the cryptographic call
boundary, such as Argon2 input, and must not be retained.

Interactive UI and CLI input must append each byte/character directly into a
`SecretString` and immediately clear the temporary input buffer. Environment
variable password support is an automation/testing escape hatch; it must use
`SecretString::from_env` so the Rust side does not first materialize the value
as a normal `String`.

### 0.2 Rust Development Rules
Rust changes must follow the project's local invariants first, then general
Rust idioms. The Rust API Guidelines are the baseline for public API shape, and
Clippy/rustfmt are the enforcement tools.

Required checks before Rust work is considered complete:
-   `bash rust/tools/check_required.sh`

`-D warnings` runs Clippy's default lint groups as errors. That is not the
strictest possible Clippy configuration. For deep review, public API work,
unsafe work, crypto/key handling, compression, parsers, page-cache changes, or
large refactors, also run a stricter advisory pass:

```text
bash rust/tools/clippy_advisory.sh
```

Treat findings from the advisory pass as review input. Fix correctness,
security, clarity, and maintainability issues. Do not blindly require zero
warnings from `pedantic`, `nursery`, or `cargo` until the project has explicitly
accepted each lint; these groups can be noisy or unstable across toolchain
versions.

Do not enable `clippy::restriction` wholesale. It contains policy lints rather
than a coherent idiomatic-Rust profile, and some lints conflict with normal Rust
style. Cherry-pick specific restriction lints only when they encode an actual
project rule. Existing required restriction-style rules include:
-   `#![deny(unsafe_op_in_unsafe_fn)]`
-   `#![deny(clippy::undocumented_unsafe_blocks)]`

Code style rules:
-   Prefer small, explicit `Result`-returning functions over panics in
    production paths.
-   Do not use `unwrap()` or `expect()` in production code unless a local
    invariant makes failure impossible; when used, include specific context.
-   Keep `unsafe` blocks tiny, wrapped in safe abstractions, and documented
    with `// SAFETY:` comments.
-   Keep Rust modules focused. Do not place a whole crate or large feature in
    one source file when it has separable concerns such as public types,
    allocator state, platform bindings, and tests.
-   Prefer borrowing (`&T`, `&str`, iterators) for read-only access and clone
    only at ownership boundaries.
-   Use concrete domain types for security-sensitive state rather than raw
    `Vec<u8>`/`String` values.
-   Add abstractions only when they remove real duplication or protect an
    invariant such as page-cache ownership, secret ownership, or path safety.
-   Tests should cover public APIs directly as well as through CLI flows.

Reference `docs/rust_development.md` for the selected published Rust skill
reference and the Clippy policy rationale.

### 1. Page-Based Format
The vault is divided into fixed-size "Pages" (e.g., 64KB).
-   **Independent Decryption**: Each page can be decrypted independently. This allows fetching and decrypting only the needed parts of the vault.
-   **Streaming**: The browser can request specific pages as needed.
-   **Caching**: Pages can be cached locally (e.g., in SQLite) to avoid re-downloading.

### 2. Virtual File System (VFS) Support
-   The vault acts as a backing store for a VFS.
-   The VFS maintains a mapping of `File Path` -> `Vault Offset + Length`.
-   The VFS reads from the vault by calculating which Pages contain the requested byte range.

### 3. Encryption & Security
-   **Algorithm**: AES-256-GCM (or XChaCha20-Poly1305) is recommended for authenticated encryption.
-   **Key Derivation**: Argon2id or Scrypt for deriving keys from a passphrase.
-   **Page Security**: Each page must have a unique Nonce/IV.
    -   **Nonce Generation**: Deterministic nonce based on Page Index + Salt, or random nonce stored with the page. Deterministic is preferred for space efficiency if using XChaCha20 or similar with large nonces, but for AES-GCM (12-byte nonce), storing it or deriving it carefully is needed.
    -   **Authentication**: Each page is authenticated (GCM tag) to prevent tampering.

### 4. Structure

#### Header
Fixed-size header containing:
-   **Magic Bytes**: `DVAULT`
-   **Version**: Format version (e.g., `2`)
-   **KDF Parameters**: Salt, Iterations, Memory cost, etc.
-   **Page Size**: Size of each encrypted page (e.g., 65536 bytes).
-   **TOC Pointer**: Offset to the Table of Contents (usually at the end of the file).

#### Pages
The body of the vault consists of a sequence of Pages.
-   **Page Structure**: `[Nonce (12 bytes)] [Ciphertext (N bytes)] [Auth Tag (16 bytes)]`
-   **Content**: Pages contain a continuous stream of data. Files are packed into this stream.
-   **Packing**: Small files are concatenated. A file may start in the middle of Page X and end in the middle of Page Y.

#### Table of Contents (TOC)
The TOC stores the metadata for all files in the vault.
-   **Location**: Stored at the end of the vault (allows appending).
-   **Encryption**: The TOC itself is stored in one or more encrypted pages.
-   **Content**:
    -   List of File Entries:
        -   Path (UTF-8)
    -   **Directory Structure**: **Implicit** (Full Paths).
        -   The TOC stores full paths (e.g., `photos/2023/image.jpg`).
        -   Directories are inferred from the paths.
    -   **Environment Variables**:
        -   A `Map<String, String>` stored in the TOC.
        -   Allows fast access/update without modifying file content pages.
        -   Encrypted along with the rest of the TOC.

## Browser & CLI Integration
Both the Browser and CLI will use a simple **In-Memory Index** for the Table of Contents (TOC).

-   **TOC Loading**:
    -   On open, the application reads the TOC (located at the end of the file) into memory.
    -   It builds a `Map<String, FileEntry>` or a lightweight Tree structure.
-   **Memory Usage**:
    -   A vault with 100,000 files will consume ~50-100MB of RAM. This is acceptable for modern Browsers and Desktop environments.
-   **Caching**:
    -   **Browser**: Can optionally cache decrypted Pages in memory (LRU Cache) to improve performance when seeking/reading small chunks.
    -   **CLI**: Relies on OS file buffering.
-   **Simplicity**:
    -   No external dependencies (SQLite).
    -   Pure Dart implementation.
    -   Identical logic for both platforms.

## CLI Support
The CLI tool `dvault` must support:
-   Creating a vault from a directory.
-   Extracting a vault.
-   Mounting a vault (FUSE) or serving it via HTTP (for browser testing).
-   Listing contents.
-   What methods should we allow the user to use to pass in the password?

## Efficiency for Small Files
By packing files into a continuous stream, we avoid padding overhead for small files.
-   **Overhead**: Only the per-page overhead (Nonce + Tag) and the TOC entry size.
-   **Example**: 1000 files of 100 bytes each = 100KB payload.
    -   Stored in ~2 Pages (64KB each).
    -   Overhead: ~2 * (12+16) bytes = 56 bytes for encryption + TOC size.
    -   Very efficient compared to 1000 separate encrypted blobs.
