/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:math';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/pointycastle.dart';

/// Represents an Encryption Key.
class StrongKey extends Key {
  // ignore: use_super_parameters
  StrongKey.fromPassPhrase(String passPhrase) : super.fromUtf8(passPhrase);

  Key secureStretch(Uint8List salt) =>
      stretch(256, iterationCount: 100000, salt: salt);

  @override
  Key stretch(
    int desiredKeyLength, {
    int iterationCount = 100,
    Uint8List? salt,
  }) {
    final params = Pbkdf2Parameters(salt!, iterationCount, desiredKeyLength);
    final pbkdf2 = PBKDF2KeyDerivator(Mac('SHA-512/HMAC'))..init(params);

    return Key(pbkdf2.process(bytes));
  }

  static Uint8List get generateSalt => SecureRandom(256).bytes;
}

class SecureRandom {
  SecureRandom(int length)
      : _bytes = Uint8List.fromList(
          List.generate(length, (i) => _generator.nextInt(256)),
        );
  static final Random _generator = Random.secure();
  final Uint8List _bytes;

  Uint8List get bytes => _bytes;

  int get length => _bytes.length;
}
