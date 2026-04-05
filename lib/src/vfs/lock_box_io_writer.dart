import 'dart:io';
import 'dart:typed_data';
import 'package:dvault/src/vfs/lock_box_writer.dart';

class LockBoxIOWriter implements LockBoxWriter {
  final RandomAccessFile _raf;

  LockBoxIOWriter(this._raf);

  @override
  Future<void> writeBytesAt(int offset, Uint8List bytes) async {
    await _raf.setPosition(offset);
    await _raf.writeFrom(bytes);
  }
}
