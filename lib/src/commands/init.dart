import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:dvault/src/util/generator.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/random/fortuna_random.dart';

import '../env.dart';
import '../key_file.dart';
import 'helper.dart';

class InitCommand extends Command<void> {
  static int minPassPhraseLength = 12;

  @override
  String get description =>
      '''Initialise DVault creating an RSA key pair used to encrypt/decrypt files.
  dvault init''';

  @override
  String get name => 'init';

  InitCommand() {
    argParser.addFlag('env',
        abbr: 'e',
        negatable: false,
        help:
            'If set the passphrase will be read from the ${Constants.DVAULT_PASSPHRASE} environment variable.');
  }

  @override
  void run() {
    String passPhrase;
    if (argResults['env']) {
      passPhrase = env[Constants.DVAULT_PASSPHRASE];
    } else {
      print('To protect your keys we lock them with a passphrase.');
      passPhrase = Helper.askForPassPhrase(passPhrase);
    }

    if (passPhrase.length < minPassPhraseLength) {
      printerr(red('The passphrase must be at least 16 characters long.'));
      print(argParser.usage);
      exit(1);
    }

    var keyPair = Generator().generateKeyPair();
    // printKeys(keyPair);

    KeyFile().save(keyPair.privateKey, keyPair.publicKey, passPhrase);

    print('');
    print(orange('*' * 80));
    print(orange('*'));
    print(orange(
        '* If you lose your passphrase you will irretrievably lose access to all files protected with DVault'));
    print(orange('*'));
    print(orange('*' * 80));
  }
}
