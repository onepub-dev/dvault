import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dvault/src/lockbox/file_entry.dart';

import 'lockbox_format.dart';
import 'lockbox_header.dart';
import 'lockbox_page.dart';
import 'lockbox_toc.dart';

/// Abstract base class for DVault repository implementations.
///
/// Platform-specific implementations:
/// - IORepository: CLI/VM using dart:io
/// - OPFSRepository: Browser using OPFS
/// - HttpRepository: Browser read-only using HTTP Range Requests
abstract class LockBox {
  late final SecretKey _key;
  late final LockboxHeader _header;
  late LockboxTOC _toc;
  bool _dirty = false;
  final Map<String, String> _env = {};

  /// File extension for lockbox files
  static const String extension = 'lbox';

  // Protected constructor for subclasses
  LockBox();

  /// Platform-specific file I/O methods (to be implemented by subclasses)

  /// Read bytes from the vault file at the given offset
  Future<Uint8List> readBytesAt(int offset, int length);

  /// Write bytes to the vault file at the given offset
  Future<void> writeBytesAt(int offset, Uint8List data);

  /// Get the current file size
  Future<int> getFileSize();

  /// Truncate the file to the given length
  Future<void> truncateFile(int length);

  /// Close the underlying file handle
  Future<void> closeFile();

  /// Initialize the repository (called by subclass after opening file)
  Future<void> initialize({
    required SecretKey key,
    required LockboxHeader header,
    required LockboxTOC toc,
  }) async {
    _key = key;
    _header = header;
    _toc = toc;
  }

  // Protected setter for subclasses
  set toc(LockboxTOC value) => _toc = value;

  // Protected getters for subclasses
  SecretKey get key => _key;
  LockboxHeader get header => _header;

  // Shared encryption/decryption logic (platform-agnostic)

  Future<void> close() async {
    if (_dirty) {
      await _flush();
    }
    await closeFile();
  }

  Future<void> _flush() async {
    if (!_dirty) return;

    final tocBytes = _toc.toBytes();

    int virtualStreamSize = 0;
    if (_toc.files.isNotEmpty) {
      final lastFile = _toc.files.values.reduce(
        (a, b) => a.offset + a.length > b.offset + b.length ? a : b,
      );
      virtualStreamSize = lastFile.offset + lastFile.length;
    }

    final virtualPageSize = _header.pageSize;
    final physicalPageSize = _header.pageSize + LockboxFormat.pageOverhead;

    final totalFilePages =
        (virtualStreamSize + virtualPageSize - 1) ~/ virtualPageSize;
    final totalPhysicalFilePages = totalFilePages + LockboxFormat.firstFilePage;
    final tocStartPhysicalOffset =
        _header.headerSize + (totalPhysicalFilePages * physicalPageSize);

    var currentTocOffset = 0;
    var currentTocPageIdx = totalPhysicalFilePages;

    // Write TOC pages
    while (currentTocOffset < tocBytes.length) {
      final remaining = tocBytes.length - currentTocOffset;
      final toWrite = remaining < virtualPageSize ? remaining : virtualPageSize;

      final chunk = tocBytes.sublist(
        currentTocOffset,
        currentTocOffset + toWrite,
      );
      final paddedChunk = Uint8List(virtualPageSize);
      paddedChunk.setRange(0, chunk.length, chunk);

      final encryptedPage = await LockboxPage.encrypt(
        data: paddedChunk,
        key: _key,
        pageIndex: currentTocPageIdx,
        pageSize: virtualPageSize,
      );

      final offset =
          tocStartPhysicalOffset +
          (currentTocOffset ~/ virtualPageSize) * physicalPageSize;
      await writeBytesAt(offset, encryptedPage);

      currentTocOffset += toWrite;
      currentTocPageIdx++;
    }

    // Truncate file to remove old TOC
    final newFileSize =
        tocStartPhysicalOffset +
        ((currentTocOffset + virtualPageSize - 1) ~/ virtualPageSize) *
            physicalPageSize;
    await truncateFile(newFileSize);

    // Update header
    final newHeader = LockboxHeader(
      version: _header.version,
      pageSize: _header.pageSize,
      tocOffset: tocStartPhysicalOffset,
      recipients: _header.recipients,
    );

    await writeBytesAt(0, newHeader.toBytes());
    _dirty = false;
  }

  // VFS Operations
  bool exists(String path) => _toc.files.containsKey(path);

  FileEntry? stat(String path) => _toc.files[path];

  Future<Uint8List> read(String path) async {
    final entry = _toc.files[path];
    if (entry == null) throw Exception('File not found: $path');

    final buffer = BytesBuilder();
    var currentOffset = entry.offset;
    var remaining = entry.length;

    while (remaining > 0) {
      final virtualPageSize = _header.pageSize;
      final physicalPageSize = _header.pageSize + LockboxFormat.pageOverhead;

      final pageIdx = currentOffset ~/ virtualPageSize;
      final offsetInPage = currentOffset % virtualPageSize;
      final physicalPageIdx = pageIdx + LockboxFormat.firstFilePage;
      final physicalOffset =
          _header.headerSize + (physicalPageIdx * physicalPageSize);

      final encryptedBytes = await readBytesAt(
        physicalOffset,
        physicalPageSize,
      );
      if (encryptedBytes.isEmpty) break;

      final decryptedPage = await LockboxPage.decrypt(
        encryptedPage: encryptedBytes,
        key: _key,
        pageIndex: physicalPageIdx,
      );

      final availableInPage = decryptedPage.length - offsetInPage;
      final toRead = remaining < availableInPage ? remaining : availableInPage;

      buffer.add(decryptedPage.sublist(offsetInPage, offsetInPage + toRead));

      currentOffset += toRead;
      remaining -= toRead;
    }

    return buffer.toBytes();
  }

  Future<void> write(String path, Uint8List data) async {
    int virtualStreamSize = 0;
    if (_toc.files.isNotEmpty) {
      final lastFile = _toc.files.values.reduce(
        (a, b) => a.offset + a.length > b.offset + b.length ? a : b,
      );
      virtualStreamSize = lastFile.offset + lastFile.length;
    }

    final startOffset = virtualStreamSize;
    final length = data.length;

    var written = 0;
    var currentOffset = startOffset;

    final virtualPageSize = _header.pageSize;
    final physicalPageSize = _header.pageSize + LockboxFormat.pageOverhead;

    while (written < length) {
      final pageIdx = currentOffset ~/ virtualPageSize;
      final offsetInPage = currentOffset % virtualPageSize;
      final physicalPageIdx = pageIdx + LockboxFormat.firstFilePage;

      Uint8List pageData;
      if (offsetInPage > 0) {
        final physicalOffset =
            _header.headerSize + (physicalPageIdx * physicalPageSize);
        final encryptedBytes = await readBytesAt(
          physicalOffset,
          physicalPageSize,
        );
        if (encryptedBytes.isNotEmpty) {
          pageData = await LockboxPage.decrypt(
            encryptedPage: encryptedBytes,
            key: _key,
            pageIndex: physicalPageIdx,
          );
        } else {
          pageData = Uint8List(virtualPageSize);
        }
      } else {
        pageData = Uint8List(virtualPageSize);
      }

      final spaceInPage = virtualPageSize - offsetInPage;
      final toWrite =
          (length - written) < spaceInPage ? (length - written) : spaceInPage;

      pageData.setRange(
        offsetInPage,
        offsetInPage + toWrite,
        data.sublist(written, written + toWrite),
      );

      final encryptedPage = await LockboxPage.encrypt(
        data: pageData,
        key: _key,
        pageIndex: pageIdx + LockboxFormat.firstFilePage,
        pageSize: virtualPageSize,
      );

      final physicalOffset =
          _header.headerSize + (physicalPageIdx * physicalPageSize);
      await writeBytesAt(physicalOffset, encryptedPage);

      written += toWrite;
      currentOffset += toWrite;
    }

    _toc.files[path] = FileEntry(
      path: path,
      offset: startOffset,
      length: length,
      created: DateTime.now().millisecondsSinceEpoch,
      modified: DateTime.now().millisecondsSinceEpoch,
    );

    _dirty = true;
    await _flush();
  }

  bool isDirectory(String path) {
    if (path == '/' || path == '') return true;
    final prefix = path.endsWith('/') ? path : '$path/';
    for (final key in _toc.files.keys) {
      if (key.startsWith(prefix)) return true;
    }
    return false;
  }

  List<String> list(String path, {bool recursive = false}) {
    final entries = <String>{};
    final prefix =
        (path == '/' || path == '')
            ? ''
            : (path.endsWith('/') ? path : '$path/');

    for (final key in _toc.files.keys) {
      if (key.startsWith(prefix)) {
        if (recursive) {
          entries.add(key);
        } else {
          final relative = key.substring(prefix.length);
          final parts = relative.split('/');
          if (parts.isNotEmpty) {
            entries.add(prefix + parts[0]);
          }
        }
      }
    }
    return entries.toList();
  }

  // Env Operations
  String? getEnv(String key) => _env[key];

  Future<void> setEnv(String key, String value) async {
    _env[key] = value;
    await _saveEnv();
  }

  Map<String, String> listEnv() => Map.unmodifiable(_env);

  Future<void> delete(String path) async {
    if (!_toc.files.containsKey(path)) {
      throw Exception('File not found: $path');
    }
    _toc.files.remove(path);
    _dirty = true;
    await _flush();
  }

  Future<void> rename(String oldPath, String newPath) async {
    if (!_toc.files.containsKey(oldPath)) {
      throw Exception('File not found: $oldPath');
    }
    if (_toc.files.containsKey(newPath)) {
      throw Exception('File already exists: $newPath');
    }
    final entry = _toc.files.remove(oldPath)!;
    _toc.files[newPath] = FileEntry(
      path: newPath,
      offset: entry.offset,
      length: entry.length,
      created: entry.created,
      modified: DateTime.now().millisecondsSinceEpoch,
    );
    _dirty = true;
    await _flush();
  }

  // Protected helpers for subclasses

  Future<void> parseEnv(Uint8List data) async {
    try {
      int len = data.length;
      while (len > 0 && data[len - 1] == 0) {
        len--;
      }
      if (len == 0) return;

      final jsonStr = String.fromCharCodes(data.sublist(0, len));
      final map = _parseJson(jsonStr) as Map;
      for (final entry in map.entries) {
        _env[entry.key.toString()] = entry.value.toString();
      }
    } catch (e) {
      // Ignore parse error (empty page)
    }
  }

  Future<void> _saveEnv() async {
    final jsonStr = _encodeJson(_env);
    final bytes = Uint8List.fromList(jsonStr.codeUnits);

    if (bytes.length > _header.pageSize) {
      throw Exception('Environment variables too large for Page 0');
    }

    final pageData = Uint8List(_header.pageSize);
    pageData.setRange(0, bytes.length, bytes);

    final encryptedPage = await LockboxPage.encrypt(
      data: pageData,
      key: _key,
      pageIndex: 0,
      pageSize: _header.pageSize,
    );

    await writeBytesAt(_header.headerSize, encryptedPage);
  }

  // Simple JSON encoding/decoding (to avoid dart:convert in web)
  static String _encodeJson(Map<String, String> map) {
    final entries = map.entries
        .map((e) => '"${_escapeJson(e.key)}":"${_escapeJson(e.value)}"')
        .join(',');
    return '{$entries}';
  }

  static String _escapeJson(String str) {
    return str
        .replaceAll('\\', '\\\\')
        .replaceAll('"', '\\"')
        .replaceAll('\n', '\\n');
  }

  static Map<String, dynamic> _parseJson(String json) {
    // Very basic JSON parser - in real implementation use dart:convert for CLI
    // and a web-compatible parser for browser
    final trimmed = json.trim();
    if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) {
      throw FormatException('Invalid JSON');
    }

    final content = trimmed.substring(1, trimmed.length - 1);
    final map = <String, dynamic>{};

    if (content.trim().isEmpty) return map;

    // Simple split on comma (doesn't handle nested objects)
    final pairs = content.split(',');
    for (final pair in pairs) {
      final parts = pair.split(':');
      if (parts.length != 2) continue;

      final key = parts[0].trim().replaceAll('"', '');
      final value = parts[1].trim().replaceAll('"', '');
      map[key] = value;
    }

    return map;
  }
}
