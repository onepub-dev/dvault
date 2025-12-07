/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */


import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';

import 'util/strong_key.dart';

class DVaultAESEncryptor {
  static const blockSize = 16;

  final IV iv;
  final Uint8List salt;
  final Key key;
  final Encrypter encryptor;

  /// Uses a pre-derived AES key (bytes) and caller-provided salt/IV.
  DVaultAESEncryptor({
    required Uint8List keyBytes,
    required Uint8List salt,
    IV? iv,
  })  : iv = iv ?? IV.fromSecureRandom(blockSize),
        salt = Uint8List.fromList(salt),
        key = Key(keyBytes),
        encryptor = Encrypter(AES(Key(keyBytes)));

  /// Convenience for deriving with Argon2id before constructing.
  static Future<DVaultAESEncryptor> fromPassphrase({
    required StrongKey passphrase,
    required Uint8List salt,
    int memoryKib = 65536,
    int iterations = 3,
    int parallelism = 1,
    int desiredKeyLength = 32,
    IV? iv,
  }) async {
    final keyBytes = await passphrase.deriveKeyBytes(
      salt: salt,
      memoryKib: memoryKib,
      iterations: iterations,
      parallelism: parallelism,
      desiredKeyLength: desiredKeyLength,
    );
    return DVaultAESEncryptor(
      keyBytes: keyBytes,
      salt: salt,
      iv: iv,
    );
  }
}
