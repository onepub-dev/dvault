import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:web/web.dart' as web;

import '../lockbox/lock_box.dart';
import '../lockbox/lockbox_format.dart';
import '../lockbox/lockbox_header.dart';
import '../lockbox/lockbox_page.dart';
import '../lockbox/lockbox_toc.dart';
import '../lockbox/recipient.dart';

/// Browser implementation using Origin Private File System (OPFS)
class OPFSLockbox extends LockBox {
  final web.FileSystemFileHandle _fileHandle;
  int _fileSize = 0;

  OPFSLockbox._(this._fileHandle);

  /// Open a vault stored in OPFS
  static Future<OPFSLockbox> open({
    required String vaultName,
    required String password,
    bool create = false,
    int pageSize = LockboxFormat.defaultPageSize,
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

    final repo = OPFSLockbox._(fileHandle);

    // Get file size
    final file = await fileHandle.getFile().toDart;
    final fileSize = file.size;

    if (create && fileSize == 0) {
      // Initialize new vault
      final salt = _generateSalt();

      // 1. Generate Random Session Key
      final randomSessionKey = SecretKey(await _generateRandomBytes(32));

      // 2. Derive Key from Password
      final passwordKey = await _deriveKey(password, salt);

      // 3. Encrypt Session Key with Password Key
      final encryptedSessionKey = await _wrapKey(randomSessionKey, passwordKey);

      final recipient = Recipient(
        type: RecipientType.password,
        keyId: salt,
        encryptedSessionKey: encryptedSessionKey,
      );

      // Create initial header to calculate size
      final tempHeader = LockboxHeader(
        version: LockboxFormat.version,
        pageSize: pageSize,
        tocOffset: 0,
        recipients: [recipient],
      );

      // Recalculate TOC offset
      final realHeaderSize = tempHeader.headerSize;
      final tocOffset =
          realHeaderSize + (pageSize + LockboxFormat.pageOverhead);

      // Final Header
      final finalHeader = LockboxHeader(
        version: LockboxFormat.version,
        pageSize: pageSize,
        tocOffset: tocOffset,
        recipients: [recipient],
      );

      final toc = LockboxTOC();

      // Get writable stream
      final writable = await fileHandle.createWritable().toDart;

      // Write Header
      await writable.write(finalHeader.toBytes().buffer.toJS).toDart;

      // Write Env Page (Page 0)
      final encryptedEnvPage = await LockboxPage.encrypt(
        data: Uint8List(0),
        key: randomSessionKey,
        pageIndex: 0,
        pageSize: pageSize,
      );
      await writable.write(encryptedEnvPage.buffer.toJS).toDart;

      await writable.close().toDart;

      await repo.initialize(
        key: randomSessionKey,
        header: finalHeader,
        toc: toc,
      );
      repo._fileSize = realHeaderSize + (pageSize + LockboxFormat.pageOverhead);
      return repo;
    } else {
      // Read existing vault
      final file = await fileHandle.getFile().toDart;
      final arrayBuffer = await file.arrayBuffer().toDart;
      final bytes = arrayBuffer.toDart.asUint8List();

      if (bytes.length < LockboxFormat.minHeaderSize) {
        throw Exception('Invalid vault file: too small');
      }

      // Parse header size from minimum bytes
      final tempMinBytes = bytes.sublist(0, LockboxFormat.minHeaderSize);
      final tempHeader = LockboxHeader.fromBytes(tempMinBytes);
      final fullHeaderSize = tempHeader.headerSize;

      if (bytes.length < fullHeaderSize) {
        throw Exception('Invalid vault file: header incomplete');
      }

      final headerBytes = bytes.sublist(0, fullHeaderSize);
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
      repo._fileSize = bytes.length;

      // Read Env Page (Page 0)
      final physicalPageSize = header.pageSize + LockboxFormat.pageOverhead;
      final envPageStart = fullHeaderSize;
      final envPageEnd = envPageStart + physicalPageSize;

      if (bytes.length >= envPageEnd) {
        final encryptedEnvPage = bytes.sublist(envPageStart, envPageEnd);
        final envData = await LockboxPage.decrypt(
          encryptedPage: encryptedEnvPage,
          key: sessionKey,
          pageIndex: 0,
        );
        await repo.parseEnv(envData);
      }

      // Read TOC
      final tocLength = bytes.length - header.tocOffset;
      if (tocLength > 0) {
        final tocBytes = <int>[];
        var offset = header.tocOffset;
        var pageIdx =
            (header.tocOffset - header.headerSize) ~/ physicalPageSize +
            LockboxFormat.firstFilePage;

        while (offset < bytes.length) {
          final pageEnd = offset + physicalPageSize;
          if (pageEnd > bytes.length) break;

          final encryptedPage = bytes.sublist(offset, pageEnd);
          final decryptedPage = await LockboxPage.decrypt(
            encryptedPage: encryptedPage,
            key: sessionKey,
            pageIndex: pageIdx,
          );

          tocBytes.addAll(decryptedPage);
          offset += physicalPageSize;
          pageIdx++;
        }

        if (tocBytes.isNotEmpty) {
          repo.toc = LockboxTOC.fromBytes(Uint8List.fromList(tocBytes));
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

  static Future<List<int>> _generateRandomBytes(int length) async {
    final bytesJS = Uint8List(length).toJS;
    web.window.crypto.getRandomValues(bytesJS);
    return bytesJS.toDart;
  }

  static List<int> _generateRandomNonce() {
    final nonceJS = Uint8List(12).toJS;
    web.window.crypto.getRandomValues(nonceJS);
    return nonceJS.toDart;
  }

  /// Wraps (encrypts) the session key with the wrapping key (KEK).
  static Future<Uint8List> _wrapKey(
    SecretKey sessionKey,
    SecretKey wrappingKey,
  ) async {
    final sessionKeyBytes = await sessionKey.extractBytes();
    final algorithm = AesGcm.with256bits();
    final nonce = _generateRandomNonce();

    final secretBox = await algorithm.encrypt(
      sessionKeyBytes,
      secretKey: wrappingKey,
      nonce: nonce,
    );

    final result = BytesBuilder();
    result.add(nonce);
    result.add(secretBox.cipherText);
    result.add(secretBox.mac.bytes);

    return result.toBytes();
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
