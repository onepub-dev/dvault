import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:web/web.dart' as web;

import '../lockbox/lock_box.dart';
import '../lockbox/lockbox_format.dart';
import '../lockbox/lockbox_header.dart';
import '../lockbox/lockbox_page.dart';
import '../lockbox/lockbox_toc.dart';
import '../lockbox/recipient.dart';

/// Read-only repository using HTTP Range Requests
class HTTPLockBox extends LockBox {
  final String _url;
  final Map<int, Uint8List> _cache = {};
  int? _fileSize;

  HTTPLockBox._(this._url);

  /// Open a remote vault via HTTP
  static Future<HTTPLockBox> open({
    required String url,
    required String password,
  }) async {
    final repo = HTTPLockBox._(url);

    // Read minimum header size
    final headers = web.Headers();
    headers.set('Range', 'bytes=0-${LockboxFormat.minHeaderSize - 1}');

    final response =
        await web.window
            .fetch(url.toJS, web.RequestInit(headers: headers))
            .toDart;

    if (!response.ok) {
      throw Exception('Failed to fetch vault: ${response.status}');
    }

    final arrayBuffer = await response.arrayBuffer().toDart;
    final minHeaderBytes = arrayBuffer.toDart.asUint8List();

    if (minHeaderBytes.length < LockboxFormat.minHeaderSize) {
      throw Exception('Invalid vault: header too small');
    }

    // Parse header size
    final tempHeader = LockboxHeader.fromBytes(minHeaderBytes);
    final fullHeaderSize = tempHeader.headerSize;

    // Read full header
    final fullHeaderHeaders = web.Headers();
    fullHeaderHeaders.set('Range', 'bytes=0-${fullHeaderSize - 1}');

    final fullHeaderResponse =
        await web.window
            .fetch(url.toJS, web.RequestInit(headers: fullHeaderHeaders))
            .toDart;

    if (!fullHeaderResponse.ok) {
      throw Exception(
        'Failed to fetch full header: ${fullHeaderResponse.status}',
      );
    }

    final fullHeaderBuffer = await fullHeaderResponse.arrayBuffer().toDart;
    final headerBytes = fullHeaderBuffer.toDart.asUint8List();

    final header = LockboxHeader.fromBytes(headerBytes);

    // Decrypt Session Key
    final recipient = header.recipients.firstWhere(
      (r) => r.type == RecipientType.password,
      orElse: () => throw Exception('No password recipient found'),
    );

    final salt = recipient.keyId;
    final passwordKey = await _deriveKey(password, salt);
    final sessionKey = await _unwrapKey(
      recipient.encryptedSessionKey,
      passwordKey,
    );

    await repo.initialize(key: sessionKey, header: header, toc: LockboxTOC());

    // Get file size from Content-Range header
    final contentRange = fullHeaderResponse.headers.get('Content-Range');
    if (contentRange != null) {
      final match = RegExp(r'bytes \d+-\d+/(\d+)').firstMatch(contentRange);
      if (match != null) {
        repo._fileSize = int.parse(match.group(1)!);
      }
    }

    // Read Env Page (Page 0)
    final physicalPageSize = header.pageSize + LockboxFormat.pageOverhead;
    final envPageStart = fullHeaderSize;

    final envPage = await repo.readBytesAt(envPageStart, physicalPageSize);
    if (envPage.length == physicalPageSize) {
      final envData = await LockboxPage.decrypt(
        encryptedPage: envPage,
        key: sessionKey,
        pageIndex: 0,
      );
      await repo.parseEnv(envData);
    }

    // Read TOC
    if (repo._fileSize != null && repo._fileSize! > header.tocOffset) {
      final toc = await repo._readTOC(header.tocOffset);
      repo.toc = toc;
    }

    return repo;
  }

  Future<LockboxTOC> _readTOC(int tocOffset) async {
    final physicalPageSize = header.pageSize + LockboxFormat.pageOverhead;

    final tocBytes = <int>[];
    var offset = tocOffset;
    var pageIndex =
        (header.tocOffset - header.headerSize) ~/ physicalPageSize +
        LockboxFormat.firstFilePage;

    // Read TOC pages (estimate max 10 pages for TOC)
    while (pageIndex < 100 && (_fileSize == null || offset < _fileSize!)) {
      try {
        final page = await readBytesAt(offset, physicalPageSize);
        if (page.length < physicalPageSize) break;

        final decrypted = await LockboxPage.decrypt(
          encryptedPage: page,
          key: key,
          pageIndex: pageIndex,
        );

        tocBytes.addAll(decrypted);
        offset += physicalPageSize;
        pageIndex++;

        // Check if we've read enough (heuristic: if last page is mostly zeros, stop)
        if (decrypted.skip(decrypted.length - 100).every((b) => b == 0)) {
          break;
        }
      } catch (e) {
        break;
      }
    }

    if (tocBytes.isEmpty) {
      return LockboxTOC();
    }

    return LockboxTOC.fromBytes(Uint8List.fromList(tocBytes));
  }

  /// Unwraps (decrypts) the session key.
  static Future<SecretKey> _unwrapKey(
    Uint8List encryptedSessionKey,
    SecretKey wrappingKey,
  ) async {
    final algorithm = AesGcm.with256bits();

    if (encryptedSessionKey.length < 12 + 16) {
      throw FormatException('Invalid encrypted key length');
    }

    final nonce = encryptedSessionKey.sublist(0, 12);
    final tag = encryptedSessionKey.sublist(encryptedSessionKey.length - 16);
    final ciphertext = encryptedSessionKey.sublist(
      12,
      encryptedSessionKey.length - 16,
    );

    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: Mac(tag));

    final sessionKeyBytes = await algorithm.decrypt(
      secretBox,
      secretKey: wrappingKey,
    );

    return SecretKey(sessionKeyBytes);
  }

  static Future<SecretKey> _deriveKey(String password, Uint8List salt) async {
    final algorithm = Argon2id(
      parallelism: 1,
      memory: 10000,
      iterations: 2,
      hashLength: 32,
    );
    return await algorithm.deriveKeyFromPassword(
      password: password,
      nonce: salt,
    );
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
    throw UnsupportedError('HTTP vaults are read-only');
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
    throw UnsupportedError('HTTP lockboxes are read-only');
  }

  @override
  Future<void> closeFile() async {
    _cache.clear();
  }

  /// Override write operations to throw UnsupportedError
  @override
  Future<void> write(String path, Uint8List data) async {
    throw UnsupportedError('HTTP lockboxes are read-only');
  }

  @override
  Future<void> delete(String path) async {
    throw UnsupportedError('HTTP lockboxes are read-only');
  }

  @override
  Future<void> rename(String oldPath, String newPath) async {
    throw UnsupportedError('HTTP lockboxes are read-only');
  }

  @override
  Future<void> setEnv(String key, String value) async {
    throw UnsupportedError('HTTP vaults are read-only');
  }
}
