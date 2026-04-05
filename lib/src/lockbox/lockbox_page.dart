import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dvault/src/lockbox/lockbox_header.dart';
import 'package:dvault/src/vfs/lock_box_reader.dart';
import 'package:dvault/src/vfs/lock_box_writer.dart';

import 'lockbox_format.dart';

/// A Lockbox is stored as a set of pages (blocks).
/// Each page can contain multiple files and a file may span multiple
/// pages. Using pages allows us to access any file without having to download
/// or decrypt the entire lockbox.
/// Each page is encrypted using AES-GCM with a unique nonce.
class LockBoxPage {
  static final _algorithm = AesGcm.with256bits();

  static const minimumSize = 1024;

  final SecretKey _key;
  final LockBoxHeader _header;
  final int pageIndex;
  final Uint8List _pageContent;

  LockBoxPage(this._header, this._key, this.pageIndex, this._pageContent);

  static Future<LockBoxPage> readPage({
    required SecretKey key,
    required int pageIndex,
    required LockBoxHeader header,
    required LockBoxReader reader,
  }) async {
    final physicalPageSize = header.pageSize;

    final physicalOffset =
        (pageIndex + LockBoxFormat.firstFilePage) * physicalPageSize;

    final encryptedPage = await reader.readBytesAt(
      physicalOffset,
      physicalPageSize,
    );

    Uint8List _data = Uint8List(0);

    if (encryptedPage.isNotEmpty) {
      //TODO: don't decrypt until someone to access the data.
      _data = await LockBoxPage.decrypt(encryptedPage: encryptedPage, key: key);
    }

    return LockBoxPage(header, key, pageIndex, _data);
  }

  bool isNotEmpty() => _pageContent.isNotEmpty;

  void writePage(LockBoxWriter writer) async {
    final encryptedData = await LockBoxPage.encrypt(
      data: _pageContent,
      key: _key,
      pageSize: _header.pageSize,
    );

    final physicalOffset = _header.headerSize + (pageIndex * _header.pageSize);
    await writer.writeBytesAt(physicalOffset, encryptedData);
  }

  static int findPage({required int offset, required LockBoxHeader header}) {
    final dataPageSize = header.pageContentSize;
    final physicalPageSize = header.pageSize;

    final pageIdx = offset ~/ dataPageSize;

    return pageIdx;
  }

  /// Encrypts a page of data.
  /// Returns the full encrypted page: [Nonce] + [Ciphertext] + [Tag]
  static Future<Uint8List> encrypt({
    required Uint8List data,
    required SecretKey key,
    required int pageSize,
  }) async {
    final maxPayload = pageSize - LockBoxFormat.pageOverhead;
    if (data.length > maxPayload) {
      throw RangeError(
        'Page payload too large: ${data.length} > $maxPayload (pageSize $pageSize)',
      );
    }

    // TODO: we only seem to be encryping the written data rather than full page?
    // this exposes info about the data size.
    // Pad payload to full payload size for consistent layout.
    final payload = Uint8List(maxPayload);
    payload.setRange(0, data.length, data);

    // Generate random nonce (12 bytes)
    // We don't strictly need pageIndex if we use a random nonce,
    // but we could include it as associated data if we wanted to bind the page to its index.
    // For now, simple random nonce.
    final nonce = _generateRandomNonce();

    final secretBox = await _algorithm.encrypt(
      payload,
      secretKey: key,
      nonce: nonce,
    );

    final page = Uint8List(pageSize);
    int offset = 0;

    // Nonce (12) - written as the first 12 bytes of the page.
    page.setRange(offset, offset + LockBoxFormat.nonceSize, nonce);
    offset += LockBoxFormat.nonceSize;

    // The encrypted data goes next.
    page.setRange(
      offset,
      offset + secretBox.cipherText.length,
      secretBox.cipherText,
    );
    offset += secretBox.cipherText.length;

    // Auth Tag/Mac (16) - written as the last 16 bytes of the page.
    page.setRange(
      pageSize - LockBoxFormat.authTagSize,
      pageSize,
      secretBox.mac.bytes,
    );

    return page;
  }

  /// Decrypts a page of data.
  /// Expects [encryptedPage] to contain: [Nonce] + [Ciphertext] + [Tag]
  static Future<Uint8List> decrypt({
    required Uint8List encryptedPage,
    required SecretKey key,
  }) async {
    if (encryptedPage.length < LockBoxFormat.pageOverhead) {
      throw FormatException('Page too short');
    }

    int offset = 0;

    // Nonce
    final nonce = encryptedPage.sublist(
      offset,
      offset + LockBoxFormat.nonceSize,
    );
    offset += LockBoxFormat.nonceSize;

    // Ciphertext + Tag
    // The cryptography package expects the MAC to be separate or part of SecretBox.
    // We need to extract the MAC (last 16 bytes).
    final macBytes = encryptedPage.sublist(
      encryptedPage.length - LockBoxFormat.authTagSize,
    );
    final cipherText = encryptedPage.sublist(
      offset,
      encryptedPage.length - LockBoxFormat.authTagSize,
    );

    final secretBox = SecretBox(cipherText, nonce: nonce, mac: Mac(macBytes));

    return Uint8List.fromList(
      await _algorithm.decrypt(secretBox, secretKey: key),
    );
  }

  /// Generates a cryptographically secure random nonce for AES-GCM encryption.
  ///
  /// Uses dart:math's Random.secure() to generate 12 truly random bytes.
  /// Each nonce MUST be unique for the same key to maintain AES-GCM security.
  static List<int> _generateRandomNonce() {
    final random = Random.secure();
    return List<int>.generate(
      LockBoxFormat.nonceSize,
      (_) => random.nextInt(256),
    );
  }

  void setContent(int offset, Uint8List fileContent) {
    _pageContent.setRange(offset, offset + fileContent.length, fileContent);
  }
}
