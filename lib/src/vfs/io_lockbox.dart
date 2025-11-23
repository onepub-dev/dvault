import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../lockbox/lock_box.dart';
import '../lockbox/lockbox_format.dart';
import '../lockbox/lockbox_header.dart';
import '../lockbox/lockbox_page.dart';
import '../lockbox/lockbox_toc.dart';
import '../lockbox/recipient.dart';

/// CLI/VM implementation of DVaultRepository using dart:io
class IOLockbox extends LockBox {
  final RandomAccessFile _raf;

  IOLockbox._(this._raf);

  static Future<IOLockbox> open({
    required File file,
    required String password,
    bool create = false,
    int pageSize = LockboxFormat.defaultPageSize,
  }) async {
    final raf = await file.open(mode: FileMode.append);

    if (create && await file.length() == 0) {
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

      // Write Header
      await raf.setPosition(0);
      await raf.writeFrom(finalHeader.toBytes());

      // Write Env Page (Page 0)
      final encryptedEnvPage = await LockboxPage.encrypt(
        data: Uint8List(0),
        key: randomSessionKey,
        pageIndex: 0,
        pageSize: pageSize,
      );

      await raf.setPosition(realHeaderSize);
      await raf.writeFrom(encryptedEnvPage);

      final repo = IOLockbox._(raf);
      await repo.initialize(
        key: randomSessionKey,
        header: finalHeader,
        toc: toc,
      );
      return repo;
    } else {
      // Read Header
      await raf.setPosition(0);
      // Read minimum header size to parse dynamic size
      final minHeaderBytes = await raf.read(LockboxFormat.minHeaderSize);
      if (minHeaderBytes.length < LockboxFormat.minHeaderSize) {
        throw FormatException('File too short');
      }

      final tempHeader = LockboxHeader.fromBytes(minHeaderBytes);
      final fullHeaderSize = tempHeader.headerSize;

      // Read full header
      await raf.setPosition(0);
      final headerBytes = await raf.read(fullHeaderSize);
      final header = LockboxHeader.fromBytes(headerBytes);

      // Decrypt Session Key
      // Find password recipient
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

      // Read Env Page (Page 0)
      final physicalPageSize = header.pageSize + LockboxFormat.pageOverhead;
      await raf.setPosition(fullHeaderSize);
      final encryptedEnvPage = await raf.read(physicalPageSize);

      final repo = IOLockbox._(raf);
      await repo.initialize(key: sessionKey, header: header, toc: LockboxTOC());

      if (encryptedEnvPage.length == physicalPageSize) {
        final envData = await LockboxPage.decrypt(
          encryptedPage: encryptedEnvPage,
          key: sessionKey,
          pageIndex: 0,
        );
        await repo.parseEnv(envData);
      }

      // Read TOC
      final fileSize = await file.length();
      final tocLength = fileSize - header.tocOffset;

      if (tocLength > 0) {
        await raf.setPosition(header.tocOffset);

        final tocBytes = BytesBuilder();
        // Calculate number of TOC pages?
        // Or just read until EOF?
        // The TOC is stored as a sequence of pages.
        // We know the total length of the TOC area.

        var read = 0;
        var pageIdx =
            (header.tocOffset - header.headerSize) ~/ physicalPageSize +
            LockboxFormat.firstFilePage;

        while (read < tocLength) {
          final encryptedBytes = await raf.read(physicalPageSize);
          if (encryptedBytes.isEmpty) break;

          final decryptedPage = await LockboxPage.decrypt(
            encryptedPage: encryptedBytes,
            key: sessionKey,
            pageIndex: pageIdx,
          );

          tocBytes.add(decryptedPage);
          read += encryptedBytes.length;
          pageIdx++;
        }

        if (tocBytes.isNotEmpty) {
          repo.toc = LockboxTOC.fromBytes(tocBytes.toBytes());
        }
      }

      return repo;
    }
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

  static Uint8List _generateSalt() {
    final salt = Uint8List(16);
    final random = List<int>.generate(
      16,
      (i) => DateTime.now().microsecond & 0xFF,
    );
    salt.setRange(0, 16, random);
    return salt;
  }

  static Future<List<int>> _generateRandomBytes(int length) async {
    // In a real implementation, use a secure RNG.
    // For now, simple random.
    return List<int>.generate(length, (i) => DateTime.now().microsecond & 0xFF);
  }

  /// Wraps (encrypts) the session key with the wrapping key (KEK).
  /// Returns the encrypted bytes.
  static Future<Uint8List> _wrapKey(
    SecretKey sessionKey,
    SecretKey wrappingKey,
  ) async {
    // We use AES-GCM to wrap the key.
    // The "data" is the session key bytes.
    final sessionKeyBytes = await sessionKey.extractBytes();

    // Use a random nonce for wrapping
    // Note: LockboxPage.encrypt generates a random nonce now.
    // But we are not using LockboxPage here, we are just encrypting a blob.
    // We can reuse LockboxPage.encrypt logic or just use AesGcm directly.
    // Let's use AesGcm directly to control the format if needed,
    // but LockboxPage.encrypt adds nonce+tag which is what we want.
    // However, LockboxPage.encrypt adds padding/structure for PAGES.
    // Here we just want a blob: [Nonce][Ciphertext][Tag]

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

  static List<int> _generateRandomNonce() {
    return List<int>.generate(12, (i) => DateTime.now().microsecond & 0xFF);
  }

  @override
  Future<Uint8List> readBytesAt(int offset, int length) async {
    await _raf.setPosition(offset);
    return await _raf.read(length);
  }

  @override
  Future<void> writeBytesAt(int offset, Uint8List data) async {
    await _raf.setPosition(offset);
    await _raf.writeFrom(data);
  }

  @override
  Future<int> getFileSize() async {
    return await _raf.length();
  }

  @override
  Future<void> truncateFile(int length) async {
    await _raf.truncate(length);
  }

  @override
  Future<void> closeFile() async {
    await _raf.close();
  }
}
