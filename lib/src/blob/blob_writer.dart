import 'dart:typed_data';

// ignore: one_member_abstracts
abstract class BlobWriter {
  Future<void> write(Uint8List data);
}
