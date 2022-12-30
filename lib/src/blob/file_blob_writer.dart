import 'dart:io';
import 'dart:typed_data';

import 'blob_writer.dart';

class FileBlobWriter implements BlobWriter {
  FileBlobWriter(this.pathToBlob);

  String pathToBlob;
  RandomAccessFile? raf;

  Future<void> _open() async {
    raf = await File(pathToBlob).open(mode: FileMode.append);
  }

  @override
  Future<void> write(Uint8List data) async {
    if (raf == null) {
      await _open();
    }
    await raf!.writeFrom(data);
  }

  Future<void> close() async {
    if (raf == null) {
      await raf!.close();
    }
  }
}
