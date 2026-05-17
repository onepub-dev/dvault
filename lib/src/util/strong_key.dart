import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:encrypt/encrypt.dart';
import 'package:collection/collection.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/pointycastle.dart';

/// Utility for deriving strong symmetric keys from passphrases.
class StrongKey {
  final Uint8List _passphraseBytes;

  StrongKey._(this._passphraseBytes);

  factory StrongKey.fromPassPhrase(Uint8List passphrase) =>
      StrongKey._(Uint8List.fromList(passphrase));

  factory StrongKey.fromUtf8(String passphrase) =>
      StrongKey._(Uint8List.fromList(utf8.encode(passphrase)));

  // Backward-compatible alias.
  factory StrongKey.fromString(String passphrase) =>
      StrongKey.fromUtf8(passphrase);

  /// Derives an `encrypt.Key` using PBKDF2-HMAC-SHA512 (synchronous).
  Key deriveEncryptKey({
    required Uint8List salt,
    int iterationCount = 1000,
    int desiredKeyLength = 32,
  }) {
    final params = Pbkdf2Parameters(salt, iterationCount, desiredKeyLength);
    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA512Digest(), 128))..init(params);
    final derived = pbkdf2.process(_passphraseBytes);
    return Key(derived);
  }

  /// Derives a [crypto.SecretKey] using Argon2id.
  Future<crypto.SecretKey> deriveSecretKey({
    int memoryKib = 65536,
    int iterations = 3,
    int parallelism = 1,
    int desiredKeyLength = 32,
    required Uint8List salt,
  }) async {
    final algorithm = crypto.Argon2id(
      memory: memoryKib,
      parallelism: parallelism,
      iterations: iterations,
      hashLength: desiredKeyLength,
    );

    return await algorithm.deriveKey(
      secretKey: crypto.SecretKey(_passphraseBytes),
      nonce: salt,
    );
  }

  /// Generates a secure random nonce of [length] bytes.
  static Uint8List generateNonce(int length) =>
      Uint8List.fromList(List.generate(length, (_) => Random.secure().nextInt(256)));

  /// Derives key bytes using Argon2id.
  Future<Uint8List> deriveKeyBytes({
    required Uint8List salt,
    int memoryKib = 65536,
    int iterations = 3,
    int parallelism = 1,
    int desiredKeyLength = 32,
  }) async {
    final secretKey = await deriveSecretKey(
      salt: salt,
      memoryKib: memoryKib,
      iterations: iterations,
      parallelism: parallelism,
      desiredKeyLength: desiredKeyLength,
    );
    final bytes = await secretKey.extractBytes();
    return Uint8List.fromList(bytes);
  }

  /// Secure random salt for key derivation.
  static Uint8List generateSalt([int length = 32]) => Uint8List.fromList(
        List.generate(length, (_) => Random.secure().nextInt(256)),
      );

  /// Returns a copy of the underlying passphrase bytes.
  Uint8List get bytes => Uint8List.fromList(_passphraseBytes);

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is StrongKey &&
        const ListEquality<int>().equals(_passphraseBytes, other._passphraseBytes);
  }

  @override
  int get hashCode => Object.hashAll(_passphraseBytes);
}
