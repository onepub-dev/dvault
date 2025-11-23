class FileEntry {
  final String path;
  final int offset;
  final int length;
  final int created; // Milliseconds since epoch
  final int modified; // Milliseconds since epoch

  FileEntry({
    required this.path,
    required this.offset,
    required this.length,
    required this.created,
    required this.modified,
  });
}
