import 'dart:typed_data';

abstract class BlobReader {
  /// length of the Blob in bytes
  Future<int> get length;

  Future<Uint8List> read(int size);

  Future<void> close();
}
