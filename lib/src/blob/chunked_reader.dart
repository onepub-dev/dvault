import 'package:async/async.dart';

import 'byte_reader.dart';

class ChunkedReader implements ByteReader {
  ChunkedStreamReader<int> stream;

  ChunkedReader(this.stream);

  @override
  Future<List<int>> readChunk(int bytes) async => stream.readChunk(bytes);

  @override
  Future<void> cancel() async => stream.cancel();
}
