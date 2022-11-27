/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../vault.dart';

class LockCommand extends Command<void> {
  LockCommand() {
    argParser
      ..addOption(
        'vault',
        abbr: 'v',
        help: '''
  The path and filename of the vault to store the file into.
    If you don't pass a vault then the [file] name will be used with a .vault extension''',
      )
      ..addFlag(
        'overwrite',
        abbr: 'o',
        negatable: false,
        help: 'Overwrites the vault if it already exists',
      )
      ..addFlag(
        'children',
        abbr: 'c',
        negatable: false,
        help: 'Include child directories and their files in vault',
      )
      ..addFlag('debug', abbr: 'd', help: 'Output debug information');
  }

  @override
  String get description => '''
Locks the passed in file by adding it to a vault.
  Generating a vault called important.vault.
    dvault lock path/to/important.txt
  
  Generate the vault in an alternate file/path
    dvault lock -v ~/mysavednotes/important.vault /path/to/important.txt

  Lock the contents of a directory into a single vault file.
    dvault lock /path/to/encrypt

  Add the contents of a directory and all its children directories and their fiiles
   into a single vault file.
    dvault lock -c /path/to/encrypt

  Overwrite the vault if it already exists.
    dvault lock -o  /path/to/important.txt

  ''';

  @override
  String get name => 'lock';

  @override
  void run() {
    Settings().setVerbose(enabled: true);
    final overwrite = argResults!['overwrite'] as bool;

    final incudeChildren = argResults!['children'] as bool;

    var vaultPath = argResults!['vault'] as String?;

    if (argResults!.rest.isEmpty) {
      printerr(red('You must pass one or more files/directories to lock'));
      print(argParser.usage);
      exit(1);
    }
    final filePaths = argResults!.rest;

    if (vaultPath == null) {
      if (filePaths.length > 1) {
        printerr(
          red('As you have passed multiple paths you must pass a vault '
              'name via the -v option'),
        );
        print(argParser.usage);
        exit(1);
      }
      final file = filePaths.first;
      // just a single file to lock, derive the vault name from the filename.
      vaultPath =
          '${join(dirname(file), basenameWithoutExtension(file))}.vault';
    }

    if (exists(vaultPath)) {
      if (overwrite) {
        delete(vaultPath);
      } else {
        printerr(
          red('The passed vault path ${truepath(vaultPath)} already exists.'),
        );
        print(argParser.usage);
        exit(1);
      }
    }

    addToVault(filePaths, vaultPath, incudeChildren: incudeChildren);
  }

  void addToVault(
    List<String> filePaths,
    String vaultPath, {
    required bool incudeChildren,
  }) {
    final vault = VaultFile(vaultPath);

    for (final filePath in filePaths) {
      if (!exists(filePath)) {
        printerr("The passed path ${truepath(filePath)} doesn't exists.");
        print(argParser.usage);
        exit(1);
      }
      if (isFile(filePath)) {
        vault.addFile(filePath);
      } else if (isDirectory(filePath)) {
        vault.addDirectory(
          pathToDirectory: filePath,
          recursive: incudeChildren,
        );
      } else {
        print('Skipping $filePath');
      }
    }
    vault.saveTo();
  }
}
