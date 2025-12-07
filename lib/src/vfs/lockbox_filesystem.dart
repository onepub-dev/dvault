import 'package:dvault/src/lockbox/lockbox.dart';
import 'package:dvault/src/vfs/lock_box_directory.dart';
import 'package:dvault/src/vfs/lock_box_file.dart';
import 'package:dvault/src/vfs/lockbox_file_stat.dart';
import 'package:file/file.dart';
import 'package:path/path.dart' as p;

class LockBoxFileSystem extends FileSystem {
  final LockBox lockbox;

  LockBoxFileSystem(this.lockbox);

  @override
  Directory directory(dynamic path) => LockBoxDirectory(this, _getPath(path));

  @override
  File file(dynamic path) => LockBoxFile(this, _getPath(path));

  @override
  Link link(dynamic path) => throw UnsupportedError('Links not supported');

  /// Convert dynamic path (String, Uri, or FileSystemEntity) to String
  String _getPath(dynamic path) {
    if (path is String) {
      return path;
    } else if (path is Uri) {
      return path.toFilePath();
    } else if (path is FileSystemEntity) {
      return path.path;
    } else {
      return path.toString();
    }
  }

  @override
  p.Context get path => p.context;

  @override
  Directory get systemTempDirectory =>
      throw UnsupportedError('Temp directory not supported');

  @override
  Directory get currentDirectory => directory('/');

  @override
  set currentDirectory(dynamic path) =>
      throw UnsupportedError('Changing CWD not supported');

  @override
  Future<FileStat> stat(String path) async {
    final entry = lockbox.stat(path);
    if (entry != null) {
      return LockBoxFileStat(
        changed: DateTime.fromMillisecondsSinceEpoch(entry.modified),
        modified: DateTime.fromMillisecondsSinceEpoch(entry.modified),
        accessed: DateTime.fromMillisecondsSinceEpoch(entry.modified),
        type: FileSystemEntityType.file,
        mode: 0x777,
        size: entry.length,
      );
    }

    if (lockbox.isDirectory(path)) {
      return LockBoxFileStat(
        changed: DateTime.now(),
        modified: DateTime.now(),
        accessed: DateTime.now(),
        type: FileSystemEntityType.directory,
        mode: 0x777,
        size: 0,
      );
    }

    return LockBoxFileStat.notFound();
  }

  @override
  FileStat statSync(String path) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<bool> identical(String path1, String path2) async => path1 == path2;

  @override
  bool identicalSync(String path1, String path2) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  Future<FileSystemEntityType> type(
    String path, {
    bool followLinks = true,
  }) async {
    final s = await stat(path);
    return s.type;
  }

  @override
  FileSystemEntityType typeSync(String path, {bool followLinks = true}) =>
      throw UnsupportedError('Sync operations not supported');

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
