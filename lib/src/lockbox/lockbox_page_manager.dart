import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dvault/src/util/strong_key.dart';

class PageManager {
  int pageSize;

  SecretKey sessionKey;

  PageManager._(this.pageSize, this.sessionKey);

  static Future<PageManager> create(int pageSize, StrongKey strongKey) async {
    // Initialize new lockbox
    final salt = StrongKey.generateSalt();

    // Derive key (caller can reuse if needed)
    await strongKey.deriveSecretKey(salt: salt);

    // Generate Random Session Key
    final sessionKey = SecretKey(await _generateRandomBytes(32));

    return PageManager._(pageSize, sessionKey);
  }

  /// Encrypts the current session key with the given wrapping key (e.g., a password key).
  Future<Uint8List> encryptSessionKey(SecretKey wrappingKey) async {
    return await wrapKey(sessionKey, wrappingKey);
  }

  static Future<List<int>> _generateRandomBytes(int length) async {
    final random = Random.secure();
    return List<int>.generate(length, (_) => random.nextInt(256));
  }

  /// Wraps (encrypts) the session key with the wrapping key (KEK).
  /// Returns the encrypted bytes.
  static Future<Uint8List> wrapKey(
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
    final nonce = StrongKey.generateNonce(12);

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
  static Future<SecretKey> unwrapKey(
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
}
