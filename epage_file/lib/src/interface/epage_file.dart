import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../core/epage_file_impl.dart';
import 'backing_store.dart';

/// The main interface for the Encrypted Page File.
///
/// Allows random access read/write operations on a file that is stored
/// as a sequence of encrypted pages.
abstract class EPageFile {
  static const int defaultPageSize = 64 * 1024;

  /// Opens an [EPageFile] backed by the given [store].
  ///
  /// [key] is the symmetric key used for encryption/decryption.
  /// [cacheSize] is the maximum number of pages to keep in memory.
  static Future<EPageFile> open(
    BackingStore store, {
    required SecretKey key,
    int cacheSize = 10,
  }) {
    return EPageFileImpl.open(store, key: key, cacheSize: cacheSize);
  }

  int get pageSize;

  /// Reads [count] bytes starting at [offset].
  Future<Uint8List> readAt(int offset, int count);

  /// Writes [buffer] starting at [offset].
  Future<void> writeAt(int offset, Uint8List buffer);

  /// Flushes any pending writes to the backing store.
  Future<void> flush();

  /// Closes the file and releases resources.
  Future<void> close();

  /// Returns the logical length of the file (user data size).
  Future<int> length();

  /// Truncates or extends the file to [length].
  Future<void> setLength(int length);
}
