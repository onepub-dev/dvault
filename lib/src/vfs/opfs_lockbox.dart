import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:typed_data';

import 'package:dvault/src/util/strong_key.dart';
import 'package:dvault/src/vfs/lock_box_writer.dart';
import 'package:dvault/src/vfs/opfs_reader.dart';
import 'package:dvault/src/vfs/opfs_writer.dart';
import 'package:web/web.dart' as web;

import '../lockbox/lockbox.dart';
import '../lockbox/lockbox_format.dart';

/// Browser implementation using Origin Private File System (OPFS)
class OPFSLockbox extends LockBox {
  final OPFSReader reader;
  int _fileSize = 0;

  OPFSLockbox._(this.reader);

  /// Open a vault stored in OPFS
  static Future<OPFSLockbox> open({
    required String lockBoxName,
    required StrongKey strongKey,
    bool create = false,
    int pageSize = LockBoxFormat.defaultPageSize,
  }) async {
    final reader = await OPFSReader.create(lockBoxName, create);
    // Get OPFS root directory
    // Get file size

    if (create && await reader.size() == 0) {
      final writer = await OPFSWriter.create(lockBoxName, create);
      // Initialize new lockbox
      return (await LockBox.createLockBox(
            strongKey: strongKey,
            pageSize: pageSize,
            writer: writer,
            create: () => OPFSLockbox._(reader),
          ))
          as OPFSLockbox;
    } else {
      // open existing lockbox.
      return (await LockBox.readLockBox(
            reader: reader,
            strongKey: strongKey,
            create: () => OPFSLockbox._(reader),
          ))
          as OPFSLockbox;
    }
  }

  @override
  Future<Uint8List> readBytesAt(int offset, int length) async {
    return reader.readBytesAt(offset, length);
  }

  @override
  Future<void> writeBytesAt(int offset, Uint8List data) async {
    ((await createWriter()) as OPFSWriter).writeBytesAt(offset, data);
  }

  @override
  Future<int> getFileSize() async {
    return _fileSize;
  }

  @override
  Future<void> truncateFile(int length) async {
    ((await createWriter()) as OPFSWriter).truncateFile(length);
  }

  @override
  Future<void> closeFile() async {
    // OPFS doesn't require explicit close
  }

  /// Check if OPFS is supported in the current browser
  static bool isSupported() {
    try {
      // Check if storage API exists and has getDirectory method
      final storage = web.window.navigator.storage;
      return (storage as JSObject).has('getDirectory');
    } catch (e) {
      return false;
    }
  }

  /// Get available storage quota information
  static Future<Map<String, int>> getStorageEstimate() async {
    final estimate = await web.window.navigator.storage.estimate().toDart;
    return {
      'usage': (estimate.usage).toInt(),
      'quota': (estimate.quota).toInt(),
    };
  }

  @override
  Future<LockBoxWriter> createWriter() async {
    return reader.createWriter();
  }
}
