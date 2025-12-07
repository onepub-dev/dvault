import 'dart:io';
import 'dart:typed_data';

import '../interface/backing_store.dart';

/// A [BackingStore] implementation that uses a local file.
class FileBackingStore implements BackingStore {
  final RandomAccessFile _raf;

  FileBackingStore(this._raf);

  /// Opens a [FileBackingStore] from a path.
  static Future<FileBackingStore> open(
    String path, {
    FileMode mode = FileMode.append,
  }) async {
    final file = File(path);
    // FileMode.append allows both read and write without truncating
    final raf = await file.open(mode: FileMode.append);
    return FileBackingStore(raf);
  }

  @override
  Future<Uint8List> read(int offset, int length) async {
    await _raf.setPosition(offset);
    final buffer = await _raf.read(length);
    if (buffer.length != length) {
      // It's okay to read less if we are at EOF, but for page reads we usually expect full pages.
      // The caller (PageManager) should handle partial reads if valid (e.g. header).
      // However, strictly speaking, read(N) in dart:io returns N bytes unless EOF.
    }
    return buffer;
  }

  @override
  Future<void> write(int offset, Uint8List buffer) async {
    await _raf.setPosition(offset);
    await _raf.writeFrom(buffer);
  }

  @override
  Future<int> length() async {
    return await _raf.length();
  }

  @override
  Future<void> flush() async {
    await _raf.flush();
  }

  @override
  Future<void> close() async {
    await _raf.close();
  }
}
