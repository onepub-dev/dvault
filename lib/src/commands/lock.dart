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

class LockCommand extends Command<void> {
  LockCommand() {
    argParser
      ..addOption(
        'vault',
        abbr: 'v',
        help: '''
  The path and filename of the vault to store the file into.
    If you don't pass a vault then the [file] name will be used with a .dvault extension''',
      )
      ..addFlag(
        'overwrite',
        abbr: 'o',
        negatable: false,
        help: 'Overwrites the vault if it already exists',
      )
      ..addFlag(
        'recurse',
        abbr: 'r',
        negatable: false,
        help: 'Encrypt child directories and their files into the vault',
      );

    addPasswordOptions(this);
  }

  @override
  String get description => '''
Locks the passed in file or directory by adding it to a vault.
  Generate a vault called important.dvault.
    dvault lock path/to/important.txt

  Generate the vault in an alternate file/path
    dvault lock --vault ~/mysavednotes/important.dvault /path/to/important.txt

  Lock the contents of a directory into a single vault file.
    dvault lock /path/to/encrypt

  Add the contents of a directory and all its children directories and their files
   into a single vault file.
    dvault lock --recurse /path/to/encrypt

  Overwrite the vault if it already exists.
    dvault lock --overwrite  /path/to/important.txt

  ''';

  @override
  String get name => 'lock';

  @override
  Future<void> run() async {
    final overwrite = argResults!['overwrite'] as bool;
    final includeChildren = argResults!['recurse'] as bool;
    var pathToVault = argResults!['vault'] as String?;

    if (argResults!.rest.isEmpty) {
      printerr(red('You must pass one or more files/directories to lock'));
      print(argParser.usage);
      exit(1);
    }
    final filePaths = argResults!.rest;

    if (pathToVault == null) {
      if (filePaths.length > 1) {
        printerr(
          red(
            'As you have passed multiple paths you must pass a vault '
            'name via the -v option',
          ),
        );
        print(argParser.usage);
        exit(1);
      }
      final file = filePaths.first;
      // just a single file to lock, derive the vault name from the filename.
      pathToVault =
          '${join(dirname(file), basenameWithoutExtension(file))}.dvault';
    }

    if (exists(pathToVault)) {
      if (overwrite) {
        delete(pathToVault);
      } else {
        printerr(
          red(
            'The passed vault path ${truepath(pathToVault)} '
            'already exists.',
          ),
        );
        print(argParser.usage);
        exit(1);
      }
    }

    await addToVault(filePaths, pathToVault, includeChildren: includeChildren);
  }

  Future<void> addToVault(
    List<String> filePaths,
    String pathToVault, {
    required bool includeChildren,
  }) async {
    // Get password
    String password;
    try {
      password = await getPassword(this);
    } catch (e) {
      printerr(red('Error getting password: $e'));
      exit(1);
    }

    // Create or open the vault
    IORepository? repo;
    try {
      final vaultFile = File(pathToVault);
      final create = !vaultFile.existsSync();

      repo = await IORepository.open(
        file: vaultFile,
        password: password,
        create: create,
      );

      // Add files to vault
      for (final filePath in filePaths) {
        if (!exists(filePath)) {
          printerr("The passed path ${truepath(filePath)} doesn't exist.");
          exit(1);
        }

        if (isFile(filePath)) {
          await _addFile(repo, filePath);
        } else if (isDirectory(filePath)) {
          await _addDirectory(repo, filePath, recursive: includeChildren);
        } else {
          print('Skipping $filePath');
        }
      }

      await repo.close();
      print(
        green(
          'Successfully locked ${filePaths.length} path(s) to $pathToVault',
        ),
      );
    } catch (e) {
      print(red('Error: $e'));
      await repo?.close();
      exit(1);
    }
  }

  Future<void> _addFile(IORepository repo, String filePath) async {
    final file = File(filePath);
    final bytes = await file.readAsBytes();
    final vaultPath = basename(filePath);

    await repo.write(vaultPath, bytes);
    print('Added: $filePath -> $vaultPath');
  }

  Future<void> _addDirectory(
    IORepository repo,
    String dirPath, {
    required bool recursive,
  }) async {
    final dir = Directory(dirPath);
    final basePath = dir.path;

    await for (final entity in dir.list(recursive: recursive)) {
      if (entity is File) {
        final bytes = await entity.readAsBytes();
        final relativePath = relative(entity.path, from: dirname(basePath));

        await repo.write(relativePath, bytes);
        print('Added: ${entity.path} -> $relativePath');
      }
    }
  }
}
