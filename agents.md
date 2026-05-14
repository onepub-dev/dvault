# DVault Design Specification

## Overview
DVault is a secure, encrypted file vault format designed for:
1.  **Streaming**: Ability to read individual files or parts of files without downloading the entire vault.
2.  **Random Access**: Efficiently seek to any byte in any file.
3.  **Small File Efficiency**: Efficient storage of many small files.
4.  **Browser Compatibility**: Designed to work with a Dart Virtual File System backed by SQLite in the browser.

## Requirements

### 0. Page Cache Ownership
All normal lockbox reads and writes must go through the page cache. The page
cache owns page encoding, encryption policy, dirty tracking, flushing, COW
replacement, zeroing of superseded physical pages, and publication of freed
ranges for reuse. Higher-level code must not write storage directly to append,
replace, redact, or update pages.

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
normal page-cache page-writing APIs. The page cache/page format layer owns the
clear-text page policy and must add and validate a checksum when writing and
reading clear-text pages.

Encrypted pages use AEAD authentication for body integrity. The page format may
also keep a public page-header checksum as an early corruption filter, but
higher-level code must not add independent checksums for encrypted page
payloads. Clear-text page payloads rely on the page-cache/page-format checksum;
clear-text object formats such as the key directory should not implement their
own nested payload checksums.

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
