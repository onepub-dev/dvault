/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */


import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';

import 'util/strong_key.dart';

class DVaultAESEncryptor {
  /// Creates an AES encryptor from [passphrase]
  /// We use this encryptor for encrypting/decrypting the text
  /// representation of the PrivateKey.
  DVaultAESEncryptor(String passphrase)
      : iv = IV.fromSecureRandom(blockSize),
        salt = StrongKey.generateSalt {
    final strongKey = StrongKey.fromPassPhrase(passphrase);

    // TODO: change interation count to 100,000 and change ui to
    // indicate the user should wait.
    // Need advice on this as using 100,000 interations takes a
    // long time. This means unlocking a file is going to take a long time.
    key = strongKey.stretch(32, iterationCount: 1000, salt: salt);
    // padding was null but I think we resolved the issue.
    encryptor = Encrypter(AES(key));
  }

  static const blockSize = 16;

  final IV iv;
  final Uint8List salt;
  late final Key key;
  late final Encrypter encryptor;
}
