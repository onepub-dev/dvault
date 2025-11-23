import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../format/dvault_format.dart';
import '../format/dvault_header.dart';
import '../format/dvault_page.dart';
import '../format/dvault_toc.dart';
import 'dvault_repository_base.dart';

/// CLI/VM implementation of DVaultRepository using dart:io
class IORepository extends DVaultRepository {
  final RandomAccessFile _raf;

  IORepository._(this._raf);

  static Future<IORepository> open({
    required File file,
    required String password,
    bool create = false,
    int pageSize = DVaultFormat.defaultPageSize,
  }) async {
    final raf = await file.open(mode: FileMode.append);

    if (create && await file.length() == 0) {
      // Initialize new vault
      final salt = Uint8List(16);
      final random = List<int>.generate(
        16,
        (i) => DateTime.now().microsecond & 0xFF,
      );
      salt.setRange(0, 16, random);

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

      // Write Header
      await raf.setPosition(0);
      await raf.writeFrom(header.toBytes());

      // Write Empty Env Page (Page 0)
      final envPageData = Uint8List(pageSize);
      final encryptedEnvPage = await DVaultPage.encrypt(
        data: envPageData,
        key: key,
        pageIndex: 0,
        salt: salt,
      );
      await raf.setPosition(DVaultFormat.headerSize);
      await raf.writeFrom(encryptedEnvPage);

      final repo = IORepository._(raf);
      await repo.initialize(key: key, header: header, toc: toc);
      return repo;
    } else {
      // Read Header
      await raf.setPosition(0);
      final headerBytes = await raf.read(DVaultFormat.headerSize);
      final header = DVaultHeader.fromBytes(headerBytes);

      final key = await _deriveKey(password, header.salt);

      // Read Env Page (Page 0)
      final physicalPageSize = header.pageSize + DVaultFormat.pageOverhead;
      await raf.setPosition(DVaultFormat.headerSize);
      final encryptedEnvPage = await raf.read(physicalPageSize);

      final repo = IORepository._(raf);
      await repo.initialize(key: key, header: header, toc: DVaultTOC());

      if (encryptedEnvPage.length == physicalPageSize) {
        final envData = await DVaultPage.decrypt(
          encryptedPage: encryptedEnvPage,
          key: key,
        );
        await repo.parseEnv(envData);
      }

      // Read TOC
      final fileSize = await file.length();
      final tocLength = fileSize - header.tocOffset;

      if (tocLength > 0) {
        await raf.setPosition(header.tocOffset);

        final tocBytes = BytesBuilder();
        final totalFilePages =
            (header.tocOffset - DVaultFormat.headerSize) ~/ physicalPageSize;
        var currentPageIdx = totalFilePages;

        var read = 0;
        while (read < tocLength) {
          final encryptedBytes = await raf.read(physicalPageSize);
          if (encryptedBytes.isEmpty) break;

          final decryptedPage = await DVaultPage.decrypt(
            encryptedPage: encryptedBytes,
            key: key,
          );

          tocBytes.add(decryptedPage);
          read += encryptedBytes.length;
          currentPageIdx++;
        }

        if (tocBytes.isNotEmpty) {
          repo.toc = DVaultTOC.fromBytes(tocBytes.toBytes());
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
