# EPageFile Design Specification

## Overview
`EPageFile` is a Dart library designed to support random access to very large encrypted files over high-latency networks. It is intended to be used in environments where streaming the entire file is not feasible. The library abstracts the underlying storage mechanism, allowing for various backing stores such as local files, HTTP services, OPFS (Origin Private File System), and IndexedDB.

## Goals
- **Random Access**: Support standard file operations like readAt and writeAt.
- **Latency Tolerance**: Optimize for high-latency networks by reading/writing in pages.
- **Encryption**: Transparent encryption/decryption of data.
- **Platform Agnostic**: Support both Dart VM (Linux, macOS, Windows) and Web.
- **Pluggable Storage**: Use adapters for different storage backends.
- **Performance**: Asynchronous writes, caching, and background processing (Isolates/Web Workers).

## Architecture

### Core Components

1.  **EPageFile**: The main class exposing the file-like API.
2.  **PageManager**: Handles caching, page alignment, and encryption/decryption.
3.  **BackingStore**: An abstract interface for the underlying storage.
4.  **StorageAdapter**: Implementations of `BackingStore` for specific backends.

### Data Structure
The file is divided into fixed-size **Pages**.
- **Page Size**: Configurable (e.g., 4KB, 16KB, 64KB).
- **Encryption**: Each page is encrypted individually using XChaCha20-Poly1305 to allow random access and data integrity.
- **Header**: A fixed-size (2KB) header is stored at the beginning of the file to track metadata (Logical Length, Page Count, Page Size).

### Caching & Buffering
- **Read Cache**: Recently used pages are kept in memory.
- **Write Cache**: Writes are buffered in memory.
    - Writes are only committed to the backing store when:
        - `flush()` is called.
        - `close()` is called.
        - A defined memory threshold is reached.
        - A timer expires.

### Concurrency
- **Asynchronous Operations**: All I/O operations are async (`Future`).
- **Background Processing**:
    - **VM**: Use `Isolate` to handle encryption and potentially I/O to avoid blocking the main UI isolate.
    - **Web**: Use `Web Worker` for similar offloading, especially for crypto operations.

## API Design

A single symmetric key is passed to the library. Key management (PKI, SSH keys, Passwords) is handled externally by the consumer (e.g., `dvault`). `EPageFile` simply uses the provided key to encrypt/decrypt pages.

```dart
abstract class EPageFile {
  /// Open an EPageFile with a specific backing store and a symmetric key.
  static Future<EPageFile> open(BackingStore store, {required SecretKey key});

  /// Read [count] bytes from the current position.
  Future<Uint8List> read(int count);

  /// Write [buffer] to the current position.
  Future<void> write(Uint8List buffer);

  /// Read [count] bytes starting at [offset].
  Future<Uint8List> readAt(int offset, int count);

  /// Write [buffer] starting at [offset].
  Future<void> writeAt(int offset, Uint8List buffer);

  /// Move the cursor to [offset].
  Future<int> seek(int offset, [SeekOrigin origin = SeekOrigin.begin]);

  /// Flush any pending writes to the backing store.
  Future<void> flush();

  /// Close the file and release resources.
  Future<void> close();

  /// The current length of the file.
  Future<int> length();
  
  /// Truncate or extend the file.
  Future<void> setLength(int length);
}
```

## Backing Store Adapters

The `BackingStore` interface defines how raw pages are read/written.

```dart
abstract class BackingStore {
  /// Read a page (or range of bytes) from the store.
  Future<Uint8List> read(int offset, int length);

  /// Write a page (or range of bytes) to the store.
  Future<void> write(int offset, Uint8List buffer);

  /// Get the amount of space consumed on the  backing store to
  ///store this file.
  Future<int> length();
}
```

### Implementations
1.  **FileBackingStore**: Uses `dart:io` `RandomAccessFile`.
2.  **HttpBackingStore**: Uses HTTP Range requests for reads. Writes might be via specific API endpoints.
3.  **OpfsBackingStore**: Uses the File System Access API (OPFS) on the Web.
    - *Note*: OPFS supports random access via `createSyncAccessHandle()` (`read` and `write` at offset).
4.  **IndexedDbBackingStore**: Stores pages as blobs/records in IndexedDB (fallback for older browsers).

## Encryption Strategy
We will use **XChaCha20-Poly1305** for authenticated encryption.

### Why XChaCha20-Poly1305?
- **Integrity**: Built-in MAC (Poly1305) ensures data hasn't been tampered with.
- **Random Nonce**: Supports a 192-bit nonce, allowing us to safely generate a random nonce for every write, preventing key/nonce reuse issues common in CTR mode.
- **Performance**: Fast and secure.

### Page Structure
Each page stored in the backing store will contain the Nonce, the Encrypted Data, and the Authentication Tag.

```text
[ Nonce (24 bytes) ] + [ Encrypted Data (N bytes) ] + [ Auth Tag (16 bytes) ]
```

**Overhead**: 40 bytes per page.
- A 4KB page becomes 4136 bytes.
- A 16KB page becomes 16424 bytes.

This overhead is negligible for the benefits of integrity and safe random-access writes.

### File Layout
```text
[ Header (2048 bytes) ] + [ Page 0 ] + [ Page 1 ] + ...
```

**Header Structure (2KB)**:
- Magic Number / Version
- Logical File Length (bytes)
- Page Count
- Page Size
- (Reserved for future use)

## Implementation Plan
1.  Define Interfaces (`EPageFile`, `BackingStore`).
2.  Implement `PageManager` with caching logic.
3.  Implement `FileBackingStore` (easiest for testing).
4.  Implement Encryption Layer.
5.  Implement `HttpBackingStore`.
6.  Implement Web Adapters (`OpfsBackingStore`).
