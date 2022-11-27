/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/random/fortuna_random.dart';

/// Class to generator RSAKeyPairs
class RSAGenerator {
  factory RSAGenerator() => _self;
  RSAGenerator._internal();
  static final RSAGenerator _self = RSAGenerator._internal();

  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateKeyPair() {
    final keyPair = getRsaKeyPair(getSecureRandom());
    return keyPair;
  }

  /// Generate a [PublicKey] and [PrivateKey] pair
  ///
  /// Returns a [AsymmetricKeyPair] based on the [RSAKeyGenerator]
  ///  with custom parameters,
  /// including a [SecureRandom]
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> getRsaKeyPair(
    SecureRandom secureRandom,
  ) {
    /// Set BitStrength to [1024, 2048 or 4096]
    final rsapars = RSAKeyGeneratorParameters(BigInt.from(65537), 4096, 5);
    final params = ParametersWithRandom(rsapars, secureRandom);
    final keyGenerator = RSAKeyGenerator()..init(params);
    final pair = keyGenerator.generateKeyPair();

    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
      pair.publicKey as RSAPublicKey,
      pair.privateKey as RSAPrivateKey,
    );
  }

  // Generates a [SecureRandom] to use in computing RSA key pair
  ///
  /// Returns [FortunaRandom] to be used in the [AsymmetricKeyPair] generation
  SecureRandom getSecureRandom() {
    final secureRandom = FortunaRandom();
    final random = Random.secure();
    final seeds = <int>[];
    for (var i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }

  void printKeys(AsymmetricKeyPair<PublicKey, PrivateKey> pair) {
    final rsaPublic = pair.publicKey as RSAPublicKey;
    final rsaPrivate = pair.privateKey as RSAPrivateKey;

    print('  Public:');
    print('    e = ${rsaPublic.exponent}'); // public exponent
    print('    n = ${rsaPublic.modulus}');
    print('  Private: n.bitlength = ${rsaPrivate.modulus!.bitLength}');
    print('    n = ${rsaPrivate.modulus}');
    print('    d = ${rsaPrivate.exponent}'); // private exponent
    print('    p = ${rsaPrivate.p}'); // the two prime numbers
    print('    q = ${rsaPrivate.q}');
  }
}
