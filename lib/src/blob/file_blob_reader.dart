import 'dart:io';
import 'dart:typed_data';

import 'package:async/async.dart';
import 'package:dcli_core/dcli_core.dart';

import 'blob_reader.dart';
import 'chunked_reader.dart';

/// Reads a Blob from a file located at [pathToFile]
/// with no interpretation of the read data.
/// The reader is buffered  by using a [ChunkedReader] to
/// optimise read performance.
class FileBlobReader implements BlobReader {
  FileBlobReader(this.pathToFile) {
    _open();
  }

  final String pathToFile;

  bool open = false;

  late final ChunkedReader _reader;

  void _open() {
    if (!open) {
      final stream = File(pathToFile).openRead();

      _reader = ChunkedReader(ChunkedStreamReader(stream));
      open = true;
    }
  }

  @override
  Future<int> get length async => stat(pathToFile).size;

  @override
  Future<Uint8List> read(int size) => _reader.stream.readBytes(size);

  @override
  Future<void> close() async {
    await _reader.cancel();
  }
}
