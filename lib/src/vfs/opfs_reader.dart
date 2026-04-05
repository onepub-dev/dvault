import 'dart:js_interop';
import 'dart:typed_data';

import 'package:dvault/src/vfs/lock_box_reader.dart';
import 'package:dvault/src/lockbox/lockbox.dart';
import 'package:dvault/src/vfs/opfs_writer.dart';
import 'package:web/web.dart' as web;

class OPFSReader implements LockBoxReader {
  final web.FileSystemFileHandle _fileHandle;

  OPFSReader(this._fileHandle) {}

  static Future<OPFSReader> create(String lockBoxName, bool create) async {
    final root = await web.window.navigator.storage.getDirectory().toDart;

    // Get or create vault file
    final fileHandle =
        await root
            .getFileHandle(
              lockBoxName,
              web.FileSystemGetFileOptions(create: create),
            )
            .toDart;

    return OPFSReader(fileHandle);
  }

  Future<Uint8List> readBytesAt(int offset, int length) async {
    final file = await _fileHandle.getFile().toDart;
    final blob = file.slice(offset, offset + length);
    final arrayBuffer = await blob.arrayBuffer().toDart;
    return arrayBuffer.toDart.asUint8List();
  }

  @override
  Future<void> close() async {
    // OPFS doesn't require explicit close
  }

  Future<int> size() async {
    final file = await _fileHandle.getFile().toDart;
    final fileSize = file.size;

    return fileSize;
  }

  Future<OPFSWriter> createWriter() async {
    return await OPFSWriter.createFromHandle(_fileHandle);
  }
}
