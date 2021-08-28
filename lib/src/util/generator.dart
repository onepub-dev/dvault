import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/random/fortuna_random.dart';

class Generator {
  static final Generator _self = Generator._internal();

  factory Generator() => _self;

  Generator._internal();

  AsymmetricKeyPair<PublicKey, PrivateKey> generateKeyPair() {
    print('Generating key pair. Be patient this can take a while.');
    var keyPair = getRsaKeyPair(getSecureRandom());

    print('Key pair generation complete');

    return keyPair;
  }

  /// Generate a [PublicKey] and [PrivateKey] pair
  ///
  /// Returns a [AsymmetricKeyPair] based on the [RSAKeyGenerator] with custom parameters,
  /// including a [SecureRandom]
  AsymmetricKeyPair<PublicKey, PrivateKey> getRsaKeyPair(
      SecureRandom secureRandom) {
    /// Set BitStrength to [1024, 2048 or 4096]
    var rsapars = RSAKeyGeneratorParameters(BigInt.from(65537), 4096, 5);
    var params = ParametersWithRandom(rsapars, secureRandom);
    var keyGenerator = RSAKeyGenerator();
    keyGenerator.init(params);
    return keyGenerator.generateKeyPair();
  }

  // Generates a [SecureRandom] to use in computing RSA key pair
  ///
  /// Returns [FortunaRandom] to be used in the [AsymmetricKeyPair] generation
  SecureRandom getSecureRandom() {
    var secureRandom = FortunaRandom();
    var random = Random.secure();
    var seeds = <int>[];
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
    print('  Private: n.bitlength = ${rsaPrivate.modulus.bitLength}');
    print('    n = ${rsaPrivate.modulus}');
    print('    d = ${rsaPrivate.exponent}'); // private exponent
    print('    p = ${rsaPrivate.p}'); // the two prime numbers
    print('    q = ${rsaPrivate.q}');
  }
}
