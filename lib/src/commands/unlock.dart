/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:dvault/src/util/strong_key.dart';
import 'package:path/path.dart';

import '../util/password_helper.dart';
import '../vfs/io_lockbox.dart';

class UnlockCommand extends Command<void> {
  UnlockCommand() {
    argParser
      ..addOption(
        'lockbox',
        abbr: 'b',
        help: 'The path and filename of the lockbox to decrypt.',
      )
      ..addOption(
        'to',
        abbr: 't',
        help: '''
    The path to store the decrypted data in.
    If not specified then the basename of the lockbox will be used.''',
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
Decrypts the passed in lockbox and extracts all files.
  dvault unlock --lockbox <lockbox_name.lockbox>
  
  Extract to a specific directory:
    dvault unlock --lockbox important.lockbox --to /path/to/extract
  ''';

  @override
  String get name => 'unlock';

  @override
  Future<void> run() async {
    final pathToLockbox = argResults!['lockbox'] as String?;

    if (pathToLockbox == null) {
      printerr("You must pass a 'lockbox' via the --lockbox option.");
      print(argParser.usage);
      exit(1);
    }

    if (!exists(pathToLockbox)) {
      printerr(
        'The passed lockbox path ${truepath(pathToLockbox)} '
        "doesn't exist.",
      );
      print(argParser.usage);
      exit(1);
    }

    var outputPath = argResults!['to'] as String?;

    // no output so use the [pathToLockbox] after stripping the .lockbox extension.
    outputPath ??= join(
      dirname(pathToLockbox),
      basenameWithoutExtension(pathToLockbox),
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
    StrongKey password;
    try {
      password = await getPassPhrase(this);
    } catch (e) {
      printerr(red('Error getting password: $e'));
      exit(1);
    }

    // Open and extract lockbox
    IOLockBox? lockbox;
    try {
      lockbox = await IOLockBox.open(
        file: File(pathToLockbox),
        strongKey: password,
      );

      // Create output directory
      createDir(outputPath, recursive: true);

      // Extract all files
      final files = lockbox.listFiles('/', recursive: true);
      var count = 0;

      for (final filePath in files) {
        if (!lockbox.isDirectory(filePath)) {
          final data = await lockbox.read(filePath);
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

      await lockbox.close();
      print(
        green(
          'Successfully extracted $count file(s) from $pathToLockbox to $outputPath',
        ),
      );
    } catch (e) {
      print(red('Error: $e'));
      await lockbox?.close();
      exit(1);
    }
  }
}
