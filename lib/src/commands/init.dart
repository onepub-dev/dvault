import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:args/command_runner.dart';
import 'package:dshell/dshell.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/random/fortuna_random.dart';

import '../env.dart';
import '../key_file.dart';
import 'helper.dart';

class InitCommand extends Command<void> {
  @override
  String get description => '''Initialise dvault creating an RSA key pair used to encrypt/decrypt files.
  dvault init''';

  @override
  String get name => 'init';

  InitCommand() {
    argParser.addFlag('env',
        abbr: 'e',
        negatable: false,
        help: 'If set the pass phrase will be read from the ${Constants.DVAULT_PASSPHRASE} environment variable.');
  }

  @override
  void run() {
    print('To protect the private key we encrypt it with a pass phrase.');
    print(orange('*' * 80));
    print(orange('*'));
    print(
        orange('* If you lose your pass phrase you will irretrievably lose access to all files encrypted with DVault'));
    print(orange('*'));
    print(orange('*' * 80));

    String passPhrase;
    if (argResults['env']) {
      passPhrase = env(Constants.DVAULT_PASSPHRASE);
    } else {
      passPhrase = Helper.askForPassPhrase(passPhrase);
    }
    if (passPhrase.length < 16) {
      printerr(red('The pass phrase must be at least 16 characters long.'));
      print(argParser.usage);
      exit(1);
    }

    var keyPair = generateKeyPair();
    printKeys(keyPair);

    KeyFile().save(keyPair.privateKey, keyPair.publicKey, passPhrase);
  }

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
  AsymmetricKeyPair<PublicKey, PrivateKey> getRsaKeyPair(SecureRandom secureRandom) {
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
