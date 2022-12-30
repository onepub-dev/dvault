abstract class ByteReader {
  Future<List<int>> readChunk(int bytes);

  void cancel();
}
