import 'dart:convert';
import 'dart:typed_data';

import 'package:dvault/src/vfs/lockbox_filesystem.dart';
import 'package:file/file.dart';

class LockBoxFile extends File {
  final LockBoxFileSystem _fs;
  @override
  final String path;

  LockBoxFile(this._fs, this.path);

  @override
  FileSystem get fileSystem => _fs;

  @override
  Future<File> create({bool recursive = false, bool exclusive = false}) async {
    // Creating a file means writing empty content
    await _fs.lockbox.addFile(path, Uint8List(0));
    return this;
  }

  @override
  void createSync({bool recursive = false, bool exclusive = false}) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<File> rename(String newPath) async {
    await _fs.lockbox.rename(path, newPath);
    return LockBoxFile(_fs, newPath);
  }

  @override
  File renameSync(String newPath) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<File> copy(String newPath) async {
    final content = await readAsBytes();
    await _fs.lockbox.addFile(newPath, content);
    return LockBoxFile(_fs, newPath);
  }

  @override
  File copySync(String newPath) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<int> length() async {
    final entry = _fs.lockbox.stat(path);
    return entry?.length ?? 0;
  }

  @override
  int lengthSync() => throw UnsupportedError('Sync operations not supported');

  @override
  Future<DateTime> lastAccessed() async {
    final entry = _fs.lockbox.stat(path);
    return entry != null
        ? DateTime.fromMillisecondsSinceEpoch(entry.modified)
        : DateTime.now();
  }

  @override
  DateTime lastAccessedSync() =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<DateTime> lastModified() async {
    final entry = _fs.lockbox.stat(path);
    return entry != null
        ? DateTime.fromMillisecondsSinceEpoch(entry.modified)
        : DateTime.now();
  }

  @override
  DateTime lastModifiedSync() =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<File> writeAsBytes(
    List<int> bytes, {
    FileMode mode = FileMode.write,
    bool flush = false,
  }) async {
    await _fs.lockbox.addFile(path, Uint8List.fromList(bytes));
    return this;
  }

  @override
  void writeAsBytesSync(
    List<int> bytes, {
    FileMode mode = FileMode.write,
    bool flush = false,
  }) => throw UnsupportedError('Sync operations not supported');

  @override
  Future<File> writeAsString(
    String contents, {
    FileMode mode = FileMode.write,
    Encoding encoding = utf8,
    bool flush = false,
  }) async {
    await writeAsBytes(encoding.encode(contents), mode: mode, flush: flush);
    return this;
  }

  @override
  void writeAsStringSync(
    String contents, {
    FileMode mode = FileMode.write,
    Encoding encoding = utf8,
    bool flush = false,
  }) => throw UnsupportedError('Sync operations not supported');

  @override
  Future<Uint8List> readAsBytes() async {
    return await _fs.lockbox.read(path);
  }

  @override
  Uint8List readAsBytesSync() =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<String> readAsString({Encoding encoding = utf8}) async {
    final bytes = await readAsBytes();
    return encoding.decode(bytes);
  }

  @override
  String readAsStringSync({Encoding encoding = utf8}) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<List<String>> readAsLines({Encoding encoding = utf8}) async {
    final content = await readAsString(encoding: encoding);
    return const LineSplitter().convert(content);
  }

  @override
  List<String> readAsLinesSync({Encoding encoding = utf8}) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<bool> exists() async {
    return _fs.lockbox.exists(path);
  }

  @override
  bool existsSync() => throw UnsupportedError('Sync operations not supported');

  @override
  Future<File> delete({bool recursive = false}) async {
    await _fs.lockbox.delete(path);
    return this;
  }

  @override
  void deleteSync({bool recursive = false}) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Stream<List<int>> openRead([int? start, int? end]) async* {
    final bytes = await readAsBytes();
    final startIdx = start ?? 0;
    final endIdx = end ?? bytes.length;
    yield bytes.sublist(startIdx, endIdx);
  }

  @override
  IOSink openWrite({FileMode mode = FileMode.write, Encoding encoding = utf8}) {
    throw UnsupportedError('openWrite not yet implemented for DVault');
  }

  @override
  RandomAccessFile openSync({FileMode mode = FileMode.read}) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<RandomAccessFile> open({FileMode mode = FileMode.read}) =>
      throw UnsupportedError('RandomAccessFile not yet implemented for DVault');

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
