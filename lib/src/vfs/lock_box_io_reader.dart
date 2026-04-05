import 'dart:io';
import 'dart:typed_data';
import 'package:dvault/src/vfs/lock_box_reader.dart';

class LockBoxIOReader implements LockBoxReader {
  final RandomAccessFile _raf;

  LockBoxIOReader(this._raf);

  @override
  Future<Uint8List> readBytesAt(int offset, int length) async {
    await _raf.setPosition(offset);
    return _raf.read(length);
  }

  @override
  Future<void> close() => _raf.close();

  Future<int> size() async => _raf.lengthSync();
}
