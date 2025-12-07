import 'dart:js_interop';
import 'dart:typed_data';

import 'package:dvault/src/vfs/lock_box_writer.dart';
import 'package:web/web.dart' as web;

class OPFSWriter implements LockBoxWriter {
  final web.FileSystemFileHandle _fileHandle;

  final web.FileSystemWritableFileStream streamWriter;

  // TODO: this isn't propery tracked
  int _fileSize = 0;

  OPFSWriter._(this._fileHandle, this.streamWriter);

  static Future<OPFSWriter> createFromHandle(
    web.FileSystemFileHandle fileHandle,
  ) async {
    final stream = await fileHandle.createWritable().toDart;
    return OPFSWriter._(fileHandle, stream);
  }

  static Future<OPFSWriter> create(String lockBoxName, bool create) async {
    final root = await web.window.navigator.storage.getDirectory().toDart;

    // Get or create vault file
    final fileHandle =
        await root
            .getFileHandle(
              lockBoxName,
              web.FileSystemGetFileOptions(create: create),
            )
            .toDart;

    return OPFSWriter.createFromHandle(fileHandle);
  }

  @override
  Future<void> writeBytesAt(int offset, Uint8List data) async {
    final writable =
        await _fileHandle
            .createWritable(
              web.FileSystemCreateWritableOptions(keepExistingData: true),
            )
            .toDart;

    await writable.seek(offset).toDart;
    await writable.write(data.buffer.toJS).toDart;
    await writable.close().toDart;

    if (offset + data.length > _fileSize) {
      _fileSize = offset + data.length;
    }
  }

  Future<void> truncateFile(int length) async {
    final writable =
        await _fileHandle
            .createWritable(
              web.FileSystemCreateWritableOptions(keepExistingData: true),
            )
            .toDart;

    await writable.truncate(length).toDart;
    await writable.close().toDart;
    _fileSize = length;
  }

  Future<void> close() async {
    await streamWriter.close().toDart;
  }
}
