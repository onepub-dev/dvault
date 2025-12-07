import 'dart:typed_data';

/// Abstract interface for the underlying storage mechanism.
///
/// This defines how raw pages are read from and written to the storage backend.
abstract class BackingStore {
  /// Reads a block of data from the store.
  ///
  /// [offset] is the byte offset in the backing store.
  /// [length] is the number of bytes to read.
  Future<Uint8List> read(int offset, int length);

  /// Writes a block of data to the store.
  ///
  /// [offset] is the byte offset in the backing store.
  /// [buffer] is the data to write.
  Future<void> write(int offset, Uint8List buffer);

  /// Returns the physical size of the backing store in bytes.
  ///
  /// This includes all overhead (headers, nonces, tags).
  Future<int> length();

  /// Flushes any buffered data to the underlying device.
  Future<void> flush();

  /// Closes the backing store.
  Future<void> close();
}
