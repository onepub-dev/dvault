import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'lockbox_format.dart';

/// A Lockbox is stored as a set of pages (blocks).
/// Each page can contain multiple files and a file may span multiple
/// pages. Using pages allows us to access any file without having to download
/// or decrypt the entire lockbox.
/// Each page is encrypted using AES-GCM with a unique nonce.
class LockboxPage {
  static final _algorithm = AesGcm.with256bits();

  /// Encrypts a page of data.
  /// Returns the full encrypted page: [Nonce] + [Ciphertext] + [Tag]
  static Future<Uint8List> encrypt({
    required Uint8List data,
    required SecretKey key,
    required int pageIndex,
    required int pageSize,
  }) async {
    // Generate random nonce (12 bytes)
    // We don't strictly need pageIndex if we use a random nonce,
    // but we could include it as associated data if we wanted to bind the page to its index.
    // For now, simple random nonce.
    final nonce = _generateRandomNonce();

    final secretBox = await _algorithm.encrypt(
      data,
      secretKey: key,
      nonce: nonce,
    );

    final result = Uint8List(
      LockboxFormat.nonceSize +
          secretBox.cipherText.length +
          LockboxFormat.authTagSize,
    );
    int offset = 0;

    // Nonce (12)
    result.setRange(offset, offset + LockboxFormat.nonceSize, nonce);
    offset += LockboxFormat.nonceSize;

    // Ciphertext
    result.setRange(
      offset,
      offset + secretBox.cipherText.length,
      secretBox.cipherText,
    );
    offset += secretBox.cipherText.length;

    // Auth Tag (16)
    result.setRange(
      offset,
      offset + LockboxFormat.authTagSize,
      secretBox.mac.bytes,
    );

    return result;
  }

  /// Decrypts a page of data.
  /// Expects [encryptedPage] to contain: [Nonce] + [Ciphertext] + [Tag]
  static Future<Uint8List> decrypt({
    required Uint8List encryptedPage,
    required SecretKey key,
    required int pageIndex,
  }) async {
    if (encryptedPage.length < LockboxFormat.pageOverhead) {
      throw FormatException('Page too short');
    }

    int offset = 0;

    // Nonce
    final nonce = encryptedPage.sublist(
      offset,
      offset + LockboxFormat.nonceSize,
    );
    offset += LockboxFormat.nonceSize;

    // Ciphertext + Tag
    // The cryptography package expects the MAC to be separate or part of SecretBox.
    // We need to extract the MAC (last 16 bytes).
    final macBytes = encryptedPage.sublist(
      encryptedPage.length - LockboxFormat.authTagSize,
    );
    final cipherText = encryptedPage.sublist(
      offset,
      encryptedPage.length - LockboxFormat.authTagSize,
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
      LockboxFormat.nonceSize,
      (_) => random.nextInt(256),
    );
  }
}
