import 'dart:io';
import 'dart:typed_data';

import 'blob_writer.dart';

class FileBlobWriter implements BlobWriter {
  String pathToBlob;

  RandomAccessFile? raf;

  FileBlobWriter(this.pathToBlob);

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
