import 'package:dvault/src/vfs/lock_box_file.dart';
import 'package:dvault/src/vfs/lockbox_filesystem.dart';
import 'package:file/file.dart';

class LockBoxDirectory extends Directory {
  final LockBoxFileSystem _fs;
  @override
  final String path;

  LockBoxDirectory(this._fs, this.path);

  @override
  FileSystem get fileSystem => _fs;

  @override
  Future<Directory> create({bool recursive = false}) async {
    // Implicit directories always exist if they have files.
    return this;
  }

  @override
  void createSync({bool recursive = false}) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<Directory> createTemp([String? prefix]) =>
      throw UnsupportedError('Temp directory not supported');

  @override
  Directory createTempSync([String? prefix]) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<Directory> rename(String newPath) =>
      throw UnsupportedError('Rename not supported');

  @override
  Directory renameSync(String newPath) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<bool> exists() async {
    return _fs.lockbox.isDirectory(path);
  }

  @override
  bool existsSync() => throw UnsupportedError('Sync operations not supported');

  @override
  Stream<FileSystemEntity> list({
    bool recursive = false,
    bool followLinks = true,
  }) async* {
    final paths = _fs.lockbox.listFiles(path, recursive: recursive);
    for (final p in paths) {
      if (_fs.lockbox.isDirectory(p)) {
        yield LockBoxDirectory(_fs, p);
      } else {
        yield LockBoxFile(_fs, p);
      }
    }
  }

  @override
  List<FileSystemEntity> listSync({
    bool recursive = false,
    bool followLinks = true,
  }) => throw UnsupportedError('Sync operations not supported');

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
