/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:encrypt/encrypt.dart';

import '../dot_vault_file.dart';
import '../env.dart';
import 'helper.dart';

class UnlockCommand extends Command<void> {
  UnlockCommand() {
    argParser
      ..addOption(
        'vault',
        abbr: 'v',
        help: 'The path and filename of the vault to decrypt.',
      )
      ..addOption(
        'file',
        abbr: 'f',
        help: '''
    The path to store the decrypted data in.
    If not specified than the basename of the vault will be used.''',
      )
      ..addFlag(
        'overwrite',
        abbr: 'o',
        negatable: false,
        help: 'Overwrites the output if it already exists',
      )
      ..addFlag(
        'env',
        abbr: 'e',
        negatable: false,
        help: 'If set the passphrase will be read from the '
            '${Constants.dvaultPassphrase} environment variable.',
      )
      ..addFlag('debug', abbr: 'd', help: 'Output debug information');
  }

  @override
  String get description => '''
Decrypts the passed in vault.
  dvault decrypt <vaultname.vault>
  ''';

  @override
  String get name => 'decrypt';

  @override
  void run() {
    Settings().setVerbose(enabled: argResults!['debug'] as bool);
    final vaultPath = argResults!['vault'] as String?;

    if (vaultPath == null) {
      printerr("You must pass a 'vault'.");
      print(argParser.usage);
      exit(1);
    }

    if (!exists(vaultPath)) {
      printerr("The passed vault path ${truepath(vaultPath)} doesn't exists.");
      print(argParser.usage);
      exit(1);
    }

    var outputPath = argResults!['file'] as String?;

    // no output so use the vaultPath after stripping the .vault extension.
    outputPath ??=
        join(dirname(vaultPath), basenameWithoutExtension(vaultPath));

    final overwrite = argResults!['overwrite'] as bool?;

    if (exists(outputPath)) {
      if (!overwrite!) {
        printerr('The output path ${truepath(outputPath)} already exists.');
        print(argParser.usage);
        exit(1);
      }
      delete(outputPath);
    }

    String? passphrase;
    if (argResults!['env'] as bool) {
      passphrase = env[Constants.dvaultPassphrase];
    } else {
      passphrase = askForPassPhrase();
    }
    if (passphrase!.length < 16) {
      printerr(red('The passphrase must be at least 16 characters long.'));
      print(argParser.usage);
      exit(1);
    }

    final keyPair = DotVaultFile.load();

    final encrypter =
        Encrypter(RSA(privateKey: keyPair.privateKey(passphrase: passphrase)));

    final file = File(vaultPath);
    final encrypted = file.readAsBytesSync();
    final contents = encrypter.decryptBytes(Encrypted(encrypted));

    File(outputPath).writeAsBytesSync(contents);
  }
}
