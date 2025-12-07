import 'dart:typed_data';

abstract class LockBoxWriter {
  Future<void> writeBytesAt(int offset, Uint8List bytes);
}
