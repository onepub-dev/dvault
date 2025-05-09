/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:path/path.dart';

import '../env.dart';
import '../security_box/security_box.dart';
import 'helper.dart';

class UnlockCommand extends Command<void> {
  UnlockCommand() {
    argParser
      ..addOption(
        'box',
        abbr: 'b',
        help: 'The path and filename of the security box to decrypt.',
      )
      ..addOption(
        'to',
        abbr: 't',
        help: '''
    The path to store the decrypted data in.
    If not specified than the basename of the security box will be used.''',
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
        help: '''
If set the passphrase will be read from the 
${Constants.dvaultPassphraseEnvKey} environment variable.
otherwise the user will be prompted to enter the passphrase''',
      )
      ..addFlag('debug', abbr: 'd', help: 'Output debug information');
  }

  @override
  String get description => '''
Decrypts the passed in security box.
  dvault decrypt <box_name.sbox>
  ''';

  @override
  String get name => 'unlock';

  @override
  Future<void> run() async {
    Settings().setVerbose(enabled: argResults!['debug'] as bool);
    final pathToSecurityBox = argResults!['box'] as String?;

    if (pathToSecurityBox == null) {
      printerr("You must pass a 'security box' via the --box option.");
      print(argParser.usage);
      exit(1);
    }

    if (!exists(pathToSecurityBox)) {
      printerr('The passed security box path ${truepath(pathToSecurityBox)} '
          "doesn't exists.");
      print(argParser.usage);
      exit(1);
    }

    var outputPath = argResults!['to'] as String?;

    // no output so use the [pathToSecurityBox] after stripping the .sbox
    // extension.
    outputPath ??= join(dirname(pathToSecurityBox),
        basenameWithoutExtension(pathToSecurityBox));

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
      passphrase = env[Constants.dvaultPassphraseEnvKey];
    } else {
      passphrase = askForPassPhrase();
    }
    if (passphrase!.length < 16) {
      printerr(red('The passphrase must be at least 16 characters long.'));
      print(argParser.usage);
      exit(1);
    }

    await SecurityBox.load(pathToSecurityBox).loadFromDisk(outputPath);
  }
}
