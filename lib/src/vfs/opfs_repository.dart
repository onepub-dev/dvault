import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:web/web.dart' as web;

import '../format/dvault_format.dart';
import '../format/dvault_header.dart';
import '../format/dvault_page.dart';
import '../format/dvault_toc.dart';
import 'dvault_repository_base.dart';

/// Browser implementation using Origin Private File System (OPFS)
class OPFSRepository extends DVaultRepository {
  final web.FileSystemFileHandle _fileHandle;
  int _fileSize = 0;

  OPFSRepository._(this._fileHandle);

  /// Open a vault stored in OPFS
  static Future<OPFSRepository> open({
    required String vaultName,
    required String password,
    bool create = false,
    int pageSize = DVaultFormat.defaultPageSize,
  }) async {
    // Get OPFS root directory
    final root = await web.window.navigator.storage.getDirectory().toDart;

    // Get or create vault file
    final fileHandle =
        await root
            .getFileHandle(
              vaultName,
              web.FileSystemGetFileOptions(create: create),
            )
            .toDart;

    final repo = OPFSRepository._(fileHandle);

    // Get file size
    final file = await fileHandle.getFile().toDart;
    final fileSize = file.size;

    if (create && fileSize == 0) {
      // Initialize new vault
      final salt = _generateSalt();
      final kdfParams = Uint8List(16);

      final header = DVaultHeader(
        version: DVaultFormat.version,
        pageSize: pageSize,
        tocOffset:
            DVaultFormat.headerSize + (pageSize + DVaultFormat.pageOverhead),
        salt: salt,
        kdfParams: kdfParams,
      );

      final toc = DVaultTOC();
      final key = await _deriveKey(password, salt);

      // Get writable stream
      final writable = await fileHandle.createWritable().toDart;

      // Write Header
      await writable.write(header.toBytes().buffer.toJS).toDart;

      // Write Empty Env Page (Page 0)
      final envPageData = Uint8List(pageSize);
      final encryptedEnvPage = await DVaultPage.encrypt(
        data: envPageData,
        key: key,
        pageIndex: 0,
        salt: salt,
      );
      await writable.write(encryptedEnvPage.buffer.toJS).toDart;

      await writable.close().toDart;

      await repo.initialize(key: key, header: header, toc: toc);
      repo._fileSize =
          DVaultFormat.headerSize + (pageSize + DVaultFormat.pageOverhead);
      return repo;
    } else {
      // Read existing vault
      final file = await fileHandle.getFile().toDart;
      final arrayBuffer = await file.arrayBuffer().toDart;
      final bytes = arrayBuffer.toDart.asUint8List();

      if (bytes.length < DVaultFormat.headerSize) {
        throw Exception('Invalid vault file: too small');
      }

      final headerBytes = bytes.sublist(0, DVaultFormat.headerSize);
      final header = DVaultHeader.fromBytes(headerBytes);

      final key = await _deriveKey(password, header.salt);

      await repo.initialize(key: key, header: header, toc: DVaultTOC());
      repo._fileSize = bytes.length;

      // Read Env Page (Page 0)
      final physicalPageSize = header.pageSize + DVaultFormat.pageOverhead;
      final envPageStart = DVaultFormat.headerSize;
      final envPageEnd = envPageStart + physicalPageSize;

      if (bytes.length >= envPageEnd) {
        final encryptedEnvPage = bytes.sublist(envPageStart, envPageEnd);
        final envData = await DVaultPage.decrypt(
          encryptedPage: encryptedEnvPage,
          key: key,
        );
        await repo.parseEnv(envData);
      }

      // Read TOC
      if (bytes.length > header.tocOffset) {
        final tocBytes = <int>[];
        var offset = header.tocOffset;

        while (offset < bytes.length) {
          final pageEnd = offset + physicalPageSize;
          if (pageEnd > bytes.length) break;

          final encryptedPage = bytes.sublist(offset, pageEnd);
          final decryptedPage = await DVaultPage.decrypt(
            encryptedPage: encryptedPage,
            key: key,
          );

          tocBytes.addAll(decryptedPage);
          offset += physicalPageSize;
        }

        if (tocBytes.isNotEmpty) {
          repo.toc = DVaultTOC.fromBytes(Uint8List.fromList(tocBytes));
        }
      }

      return repo;
    }
  }

  static Uint8List _generateSalt() {
    final saltJS = Uint8List(16).toJS;
    web.window.crypto.getRandomValues(saltJS);
    return saltJS.toDart;
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
    final file = await _fileHandle.getFile().toDart;
    final blob = file.slice(offset, offset + length);
    final arrayBuffer = await blob.arrayBuffer().toDart;
    return arrayBuffer.toDart.asUint8List();
  }

  @override
  Future<void> writeBytesAt(int offset, Uint8List data) async {
    final writable =
        await _fileHandle
            .createWritable(
              web.FileSystemCreateWritableOptions(keepExistingData: true),
            )
            .toDart;

    await writable.seek(offset).toDart;
    await writable.write(data.buffer.toJS).toDart;
    await writable.close().toDart;

    if (offset + data.length > _fileSize) {
      _fileSize = offset + data.length;
    }
  }

  @override
  Future<int> getFileSize() async {
    return _fileSize;
  }

  @override
  Future<void> truncateFile(int length) async {
    final writable =
        await _fileHandle
            .createWritable(
              web.FileSystemCreateWritableOptions(keepExistingData: true),
            )
            .toDart;

    await writable.truncate(length).toDart;
    await writable.close().toDart;
    _fileSize = length;
  }

  @override
  Future<void> closeFile() async {
    // OPFS doesn't require explicit close
  }

  /// Check if OPFS is supported in the current browser
  static bool isSupported() {
    try {
      // Check if storage API exists and has getDirectory method
      final storage = web.window.navigator.storage;
      return (storage as JSObject).has('getDirectory');
    } catch (e) {
      return false;
    }
  }

  /// Get available storage quota information
  static Future<Map<String, int>> getStorageEstimate() async {
    final estimate = await web.window.navigator.storage.estimate().toDart;
    return {
      'usage': (estimate.usage).toInt(),
      'quota': (estimate.quota).toInt(),
    };
  }
}
