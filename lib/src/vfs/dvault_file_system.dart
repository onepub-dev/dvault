import 'package:dvault/src/vfs/d_vault_file.dart';
import 'package:dvault/src/vfs/d_vault_file_stat.dart';
import 'package:dvault/src/vfs/dvault_repository_base.dart';
import 'package:file/file.dart';
import 'package:path/path.dart' as p;

class DVaultFileSystem extends FileSystem {
  final DVaultRepository repo;

  DVaultFileSystem(this.repo);

  @override
  Directory directory(dynamic path) => DVaultDirectory(this, _getPath(path));

  @override
  File file(dynamic path) => DVaultFile(this, _getPath(path));

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
    final entry = repo.stat(path);
    if (entry != null) {
      return DVaultFileStat(
        changed: DateTime.fromMillisecondsSinceEpoch(entry.modified),
        modified: DateTime.fromMillisecondsSinceEpoch(entry.modified),
        accessed: DateTime.fromMillisecondsSinceEpoch(entry.modified),
        type: FileSystemEntityType.file,
        mode: 0x777,
        size: entry.length,
      );
    }

    if (repo.isDirectory(path)) {
      return DVaultFileStat(
        changed: DateTime.now(),
        modified: DateTime.now(),
        accessed: DateTime.now(),
        type: FileSystemEntityType.directory,
        mode: 0x777,
        size: 0,
      );
    }

    return DVaultFileStat.notFound();
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

class DVaultDirectory extends Directory {
  final DVaultFileSystem _fs;
  @override
  final String path;

  DVaultDirectory(this._fs, this.path);

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
    return _fs.repo.isDirectory(path);
  }

  @override
  bool existsSync() => throw UnsupportedError('Sync operations not supported');

  @override
  Stream<FileSystemEntity> list({
    bool recursive = false,
    bool followLinks = true,
  }) async* {
    final paths = _fs.repo.list(path, recursive: recursive);
    for (final p in paths) {
      if (_fs.repo.isDirectory(p)) {
        yield DVaultDirectory(_fs, p);
      } else {
        yield DVaultFile(_fs, p);
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
