import 'dart:io';
import 'dart:typed_data';

import 'byte_writer.dart';

class RafWriter implements ByteWriter {
  RafWriter(this.raf);

  RandomAccessFile raf;

  @override
  void write(Uint8List data) {
    raf.writeFromSync(data);
  }
}
