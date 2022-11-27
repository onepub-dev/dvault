/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../dot_vault_file.dart';
import '../env.dart';
import '../rsa/rsa_generator.dart';
import '../util/messages.dart';
import 'helper.dart';

class InitCommand extends Command<void> {
  InitCommand() {
    argParser.addFlag(
      'env',
      abbr: 'e',
      negatable: false,
      help: 'If set the passphrase will be read from the '
          '${Constants.dvaultPassphrase} environment variable.',
    );
  }
  static int minPassPhraseLength = 12;

  @override
  String get description => '''
  Initialise DVault creating an RSA key pair used to encrypt/decrypt files.
  dvault init''';

  @override
  String get name => 'init';

  @override
  void run() {
    if (exists(DotVaultFile.storagePath)) {
      print(red('${'*' * 40}  WARNING  ${'*' * 40}'));
      print(orange('Your .dvault file already exists.'));
      print(
        orange('If you continue you will lose access to all existing vaults.'),
      );
      print(blue("If you want to change your passphrase use 'dvault reset'."));
      if (!confirm(
        red('Are you sure you want to lose access to existing vaults?'),
      )) {
        print('Init stopped.');
        exit(1);
      } else {
        backupFile(DotVaultFile.storagePath);
        print('');
        print(
          blue('Your .dvault file has been backed up to a .bak subdirectory'),
        );
        print('');
        delete(DotVaultFile.storagePath);
      }
    }
    String? passPhrase;
    if (argResults!['env'] as bool) {
      passPhrase = env[Constants.dvaultPassphrase];
    } else {
      print(
        'To protect your keys we lock them with a passphrase with a '
        'minimum length of ${InitCommand.minPassPhraseLength}).',
      );
      passPhrase = askForPassPhrase();
    }

    if (passPhrase!.length < minPassPhraseLength) {
      printerr(
        red('The passphrase must be at least '
            '${InitCommand.minPassPhraseLength} characters long.'),
      );
      print(argParser.usage);
      exit(1);
    }

    print('Generating and saving key pair. Be patient this can take a while.');
    final keyPair = RSAGenerator().generateKeyPair();

    DotVaultFile.create(keyPair.privateKey, keyPair.publicKey, passPhrase);
    print('Key pair generation complete');

    printBackupMessage(DotVaultFile.storagePath);
  }
}
