import 'dart:io';

import 'byte_reader.dart';

class RafReader implements ByteReader {
  RafReader(this.raf);

  RandomAccessFile raf;

  @override
  Future<List<int>> readChunk(int bytes) async {
    final read = <int>[];

    for (var i = 0; i < bytes; i++) {
      final byte = raf.readByteSync();

      if (byte == -1) {
        break;
      }
      read.add(byte);
    }
    return Future.value(read);
  }

  @override
  void cancel() {
    /// NO-OP
  }
}
