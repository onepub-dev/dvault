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
import '../vfs/io_lockbox.dart';

class LockCommand extends Command<void> {
  LockCommand() {
    argParser
      ..addOption(
        'lockbox',
        abbr: 'b',
        help: '''
  The path and filename of the lockbox to store the file into.
    If you don't pass a lockbox then the [file] name will be used with a .lockbox extension''',
      )
      ..addFlag(
        'overwrite',
        abbr: 'o',
        negatable: false,
        help: 'Overwrites the lockbox if it already exists',
      )
      ..addFlag(
        'recurse',
        abbr: 'r',
        negatable: false,
        help: 'Encrypt child directories and their files into the lockbox',
      );

    addPasswordOptions(this);
  }

  @override
  String get description => '''
Locks the passed in file or directory by adding it to a lockbox.
  Generate a lockbox called important.lockbox.
    dvault lock path/to/important.txt

  Generate the lockbox in an alternate file/path
    dvault lock --lockbox ~/mysavednotes/important.lockbox /path/to/important.txt

  Lock the contents of a directory into a single lockbox file.
    dvault lock /path/to/encrypt

  Add the contents of a directory and all its children directories and their files
   into a single lockbox file.
    dvault lock --recurse /path/to/encrypt

  Overwrite the lockbox if it already exists.
    dvault lock --overwrite  /path/to/important.txt

  ''';

  @override
  String get name => 'lock';

  @override
  Future<void> run() async {
    final overwrite = argResults!['overwrite'] as bool;
    final includeChildren = argResults!['recurse'] as bool;
    var pathToLockbox = argResults!['lockbox'] as String?;

    if (argResults!.rest.isEmpty) {
      printerr(red('You must pass one or more files/directories to lock'));
      print(argParser.usage);
      exit(1);
    }
    final filePaths = argResults!.rest;

    if (pathToLockbox == null) {
      if (filePaths.length > 1) {
        printerr(
          red(
            'As you have passed multiple paths you must pass a lockbox '
            'name via the -b option',
          ),
        );
        print(argParser.usage);
        exit(1);
      }
      final file = filePaths.first;
      // just a single file to lock, derive the lockbox name from the filename.
      pathToLockbox =
          '${join(dirname(file), basenameWithoutExtension(file))}.lbox';
    }

    if (exists(pathToLockbox)) {
      if (overwrite) {
        delete(pathToLockbox);
      } else {
        printerr(
          red(
            'The passed lockbox path ${truepath(pathToLockbox)} '
            'already exists.',
          ),
        );
        print(argParser.usage);
        exit(1);
      }
    }

    await addToLockbox(filePaths, pathToLockbox, includeChildren: includeChildren);
  }

  Future<void> addToLockbox(
    List<String> filePaths,
    String pathToLockbox, {
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

    // Create or open the lockbox
    IOLockbox? repo;
    try {
      final lockboxFile = File(pathToLockbox);
      final create = !lockboxFile.existsSync();

      repo = await IOLockbox.open(
        file: lockboxFile,
        password: password,
        create: create,
      );

      // Add files to lockbox
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
          'Successfully locked ${filePaths.length} path(s) to $pathToLockbox',
        ),
      );
    } catch (e) {
      print(red('Error: $e'));
      await repo?.close();
      exit(1);
    }
  }

  Future<void> _addFile(IOLockbox repo, String filePath) async {
    final file = File(filePath);
    final bytes = await file.readAsBytes();
    final lockboxPath = basename(filePath);

    await repo.write(lockboxPath, bytes);
    print('Added: $filePath -> $lockboxPath');
  }

  Future<void> _addDirectory(
    IOLockbox repo,
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
