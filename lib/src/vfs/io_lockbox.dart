import 'dart:io';
import 'dart:typed_data';

import 'package:dvault/src/vfs/lock_box_reader.dart';
import 'package:dvault/src/util/strong_key.dart';
import 'package:dvault/src/vfs/lock_box_io_reader.dart';
import 'package:dvault/src/vfs/lock_box_io_writer.dart';
import 'package:dvault/src/vfs/lock_box_writer.dart';

import '../lockbox/lockbox.dart';
import '../lockbox/lockbox_format.dart';

/// CLI/VM implementation of DVaultRepository using dart:io
class IOLockBox extends LockBox {
  final RandomAccessFile _raf;

  IOLockBox._(this._raf);

  static Future<IOLockBox> open({
    required File file,
    required StrongKey strongKey,
    bool create = false,
    int pageSize = LockBoxFormat.defaultPageSize,
  }) async {
    final raf = await file.open(mode: FileMode.append);

    if (create && await file.length() == 0) {
      final writer = LockBoxIOWriter(raf);
      // Initialize new lockbox
      return (await LockBox.createLockBox(
            strongKey: strongKey,
            pageSize: pageSize,
            writer: writer,
            create: () => IOLockBox._(raf),
          ))
          as IOLockBox;
    } else {
      final reader = LockBoxIOReader(raf);
      // open existing lockbox.
      return (await LockBox.readLockBox(
            reader: reader,
            strongKey: strongKey,
            create: () => IOLockBox._(raf),
          ))
          as IOLockBox;
    }
  }

  Future<LockBoxWriter> createWriter() async => LockBoxIOWriter(_raf);

  @override
  Future<Uint8List> readBytesAt(int offset, int length) async {
    await _raf.setPosition(offset);
    return await _raf.read(length);
  }

  @override
  Future<void> writeBytesAt(int offset, Uint8List data) async {
    await _raf.setPosition(offset);
    await _raf.writeFrom(data);
  }

  @override
  Future<int> getFileSize() async {
    return await _raf.length();
  }

  @override
  Future<void> truncateFile(int length) async {
    await _raf.truncate(length);
  }

  @override
  Future<void> closeFile() async {
    await _raf.close();
  }
}
