import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dvault/src/util/byte_data_helper.dart';

import 'lockbox_format.dart';

class DVaultPage {
  static final _algorithm = AesGcm.with256bits();

  /// Encrypts a page of data.
  /// Returns the full encrypted page: [Nonce] + [Ciphertext] + [Tag]
  static Future<Uint8List> encrypt({
    required Uint8List data,
    required SecretKey key,
    required int pageIndex,
    required Uint8List salt,
  }) async {
    // Generate deterministic nonce: Hash(Salt + PageIndex) -> 12 bytes
    final nonce = _generateNonce(pageIndex, salt);

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

  /// Generates a deterministic nonce based on page index and salt.
  /// We use a simple XOR/Hash combination or just the index if safe.
  /// For AES-GCM, nonce uniqueness is critical.
  /// We'll use the first 12 bytes of the salt XORed with the page index.
  static List<int> _generateNonce(int pageIndex, Uint8List salt) {
    final nonce = Uint8List(LockboxFormat.nonceSize);

    // Copy first 12 bytes of salt (or pad if short, but salt is 16 bytes)
    for (int i = 0; i < LockboxFormat.nonceSize; i++) {
      nonce[i] = salt[i];
    }

    // XOR the page index into the last 8 bytes (little endian)
    final data = ByteData.view(nonce.buffer);
    // We only have 12 bytes. Let's use the last 8 bytes for the counter.
    // Bytes 4-11.
    final current = ByteDataHelper.getUint64(data, 4, Endian.little);
    ByteDataHelper.setUint64(data, 4, current ^ pageIndex, Endian.little);

    return nonce;
  }
}
