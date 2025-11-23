/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:path/path.dart';

import '../util/password_helper.dart';
import '../vfs/io_repository.dart';

class UnlockCommand extends Command<void> {
  UnlockCommand() {
    argParser
      ..addOption(
        'vault',
        abbr: 'v',
        help: 'The path and filename of the vault to decrypt.',
      )
      ..addOption(
        'to',
        abbr: 't',
        help: '''
    The path to store the decrypted data in.
    If not specified then the basename of the vault will be used.''',
      )
      ..addFlag(
        'overwrite',
        abbr: 'o',
        negatable: false,
        help: 'Overwrites the output if it already exists',
      );

    addPasswordOptions(this);
  }

  @override
  String get description => '''
Decrypts the passed in vault and extracts all files.
  dvault unlock --vault <vault_name.dvault>
  
  Extract to a specific directory:
    dvault unlock --vault important.dvault --to /path/to/extract
  ''';

  @override
  String get name => 'unlock';

  @override
  Future<void> run() async {
    final pathToVault = argResults!['vault'] as String?;

    if (pathToVault == null) {
      printerr("You must pass a 'vault' via the --vault option.");
      print(argParser.usage);
      exit(1);
    }

    if (!exists(pathToVault)) {
      printerr(
        'The passed vault path ${truepath(pathToVault)} '
        "doesn't exist.",
      );
      print(argParser.usage);
      exit(1);
    }

    var outputPath = argResults!['to'] as String?;

    // no output so use the [pathToVault] after stripping the .dvault extension.
    outputPath ??= join(
      dirname(pathToVault),
      basenameWithoutExtension(pathToVault),
    );

    final overwrite = argResults!['overwrite'] as bool;

    if (exists(outputPath)) {
      if (!overwrite) {
        printerr('The output path ${truepath(outputPath)} already exists.');
        print(argParser.usage);
        exit(1);
      }

      // Delete existing output
      if (isDirectory(outputPath)) {
        deleteDir(outputPath);
      } else {
        delete(outputPath);
      }
    }

    // Get password
    String password;
    try {
      password = await getPassword(this);
    } catch (e) {
      printerr(red('Error getting password: $e'));
      exit(1);
    }

    // Open and extract vault
    IORepository? repo;
    try {
      repo = await IORepository.open(
        file: File(pathToVault),
        password: password,
      );

      // Create output directory
      createDir(outputPath, recursive: true);

      // Extract all files
      final files = repo.list('/', recursive: true);
      var count = 0;

      for (final filePath in files) {
        if (!repo.isDirectory(filePath)) {
          final data = await repo.read(filePath);
          final outputFilePath = join(outputPath, filePath);

          // Create parent directories if needed
          final parentDir = dirname(outputFilePath);
          if (!exists(parentDir)) {
            createDir(parentDir, recursive: true);
          }

          // Write file
          File(outputFilePath).writeAsBytesSync(data);
          print('Extracted: $filePath -> $outputFilePath');
          count++;
        }
      }

      await repo.close();
      print(
        green(
          'Successfully extracted $count file(s) from $pathToVault to $outputPath',
        ),
      );
    } catch (e) {
      print(red('Error: $e'));
      await repo?.close();
      exit(1);
    }
  }
}
