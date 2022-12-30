

// /// Read a table of content from a security box.
// class TocBlobReader implements BlobReader {
//   TocBlobReader(this.tableOfContent);

//   final TableOfContent tableOfContent;

//   bool open = false;

//   late final ChunkedReader _reader;

//   // void _open() {
//   //   if (!open) {
//   //     final stream = File(pathToFile).openRead();

//   //     _reader = ChunkedReader(ChunkedStreamReader(stream));
//   //     open = true;
//   //   }
//   // }

//   @override
//   Future<int> get length async => (await stat(pathToFile)).size;

//   @override
//   Future<Uint8List> read(int size) => _reader.stream.readBytes(size);

//   void _convert() {
//     final sb = StringBuffer();
//     for (final tocEntry in tableOfContent.entries) {
//       sb.write(tocEntry.)
//     }
//   }

//   @override
//   Future<void> close() async {
//     await _reader.cancel();
//   }
// }
