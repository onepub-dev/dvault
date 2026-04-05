import 'dart:js_interop';
import 'dart:typed_data';

import 'package:dvault/src/util/strong_key.dart';
import 'package:dvault/src/vfs/lock_box_reader.dart';
import 'package:dvault/src/vfs/lock_box_writer.dart';
import 'package:web/web.dart' as web;

import '../lockbox/lockbox.dart';

class HTTPLockBoxReader implements LockBoxReader {
  final String _url;

  late final int _fileSize;

  HTTPLockBoxReader(this._url);

  @override
  Future<void> close() async {}

  @override
  Future<Uint8List> readBytesAt(int offset, int length) async {
    final headers = web.Headers();
    headers.set('Range', 'bytes=$offset-${offset + length - 1}');

    final response =
        await web.window
            .fetch(_url.toJS, web.RequestInit(headers: headers))
            .toDart;

    if (!response.ok) {
      throw Exception('Failed to fetch LockBox: ${response.status}');
    }

    final arrayBuffer = await response.arrayBuffer().toDart;

    // Get file size from Content-Range header
    final contentRange = response.headers.get('Content-Range');
    if (contentRange != null) {
      final match = RegExp(r'bytes \d+-\d+/(\d+)').firstMatch(contentRange);
      if (match != null) {
        _fileSize = int.parse(match.group(1)!);
      }
    }
    return arrayBuffer.toDart.asUint8List();
  }

  @override
  Future<int> size() async {
    return _fileSize;
  }
}

/// Read-only repository using HTTP Range Requests
class HTTPLockBox extends LockBox {
  final String _url;
  final Map<int, Uint8List> _cache = {};
  int? _fileSize;

  HTTPLockBox._(this._url);

  /// Open a remote vault via HTTP
  static Future<HTTPLockBox> open({
    required StrongKey strongKey,
    required String url,
  }) async {
    final reader = HTTPLockBoxReader(url);

    return (await LockBox.readLockBox(
          reader: reader,
          strongKey: strongKey,
          create: () => HTTPLockBox._(url),
        ))
        as HTTPLockBox;
  }

  @override
  Future<Uint8List> readBytesAt(int offset, int length) async {
    // Check cache
    final cacheKey = (offset ~/ 4096) * 4096; // 4KB cache blocks
    if (_cache.containsKey(cacheKey)) {
      final cached = _cache[cacheKey]!;
      final relativeOffset = offset - cacheKey;
      if (relativeOffset + length <= cached.length) {
        return cached.sublist(relativeOffset, relativeOffset + length);
      }
    }

    // Fetch from server
    final headers = web.Headers();
    headers.set('Range', 'bytes=$offset-${offset + length - 1}');

    final response =
        await web.window
            .fetch(_url.toJS, web.RequestInit(headers: headers))
            .toDart;

    if (!response.ok) {
      throw Exception('Failed to read bytes: ${response.status}');
    }

    final arrayBuffer = await response.arrayBuffer().toDart;
    final data = arrayBuffer.toDart.asUint8List();

    // Cache the result
    _cache[cacheKey] = data;

    // Limit cache size
    if (_cache.length > 100) {
      final keys = _cache.keys.toList()..sort();
      _cache.remove(keys.first);
    }

    return data;
  }

  @override
  Future<void> writeBytesAt(int offset, Uint8List data) async {
    throw UnsupportedError('HTTP LockBoxes are read-only');
  }

  @override
  Future<int> getFileSize() async {
    if (_fileSize != null) return _fileSize!;

    // Send HEAD request to get file size
    final response =
        await web.window
            .fetch(_url.toJS, web.RequestInit(method: 'HEAD'))
            .toDart;

    final contentLength = response.headers.get('Content-Length');
    if (contentLength != null) {
      _fileSize = int.parse(contentLength);
      return _fileSize!;
    }

    throw Exception('Could not determine file size');
  }

  @override
  Future<void> truncateFile(int length) async {
    throw UnsupportedError('HTTP LockBoxes are read-only');
  }

  @override
  Future<void> closeFile() async {
    _cache.clear();
  }

  /// Override write operations to throw UnsupportedError
  @override
  Future<void> addFile(String path, Uint8List data) async {
    throw UnsupportedError('HTTP LockBoxes are read-only');
  }

  @override
  Future<void> delete(String path) async {
    throw UnsupportedError('HTTP LockBoxes are read-only');
  }

  @override
  Future<void> rename(String oldPath, String newPath) async {
    throw UnsupportedError('HTTP LockBoxes are read-only');
  }

  @override
  Future<LockBoxWriter> createWriter() async {
    // HTTP is only readonly
    throw UnimplementedError();
  }

  // @override
  // Future<void> setEnv(String key, String value) async {
  //   throw UnsupportedError('HTTP lockboxes are read-only');
  // }
}
