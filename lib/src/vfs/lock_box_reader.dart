import 'dart:typed_data';

abstract class LockBoxReader {
  Future<Uint8List> readBytesAt(int offset, int length);
  Future<void> close();
  Future<int> size();
}
