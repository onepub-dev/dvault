/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:path/path.dart';

import '../security_box/security_box.dart';

class LockCommand extends Command<void> {
  LockCommand() {
    argParser
      ..addOption(
        'box',
        abbr: 'b',
        help: '''
  The path and filename of the security box to store the file into.
    If you don't pass a security box then the [file] name will be used with a .sbox extension''',
      )
      ..addFlag(
        'overwrite',
        abbr: 'o',
        negatable: false,
        help: 'Overwrites the security box if it already exists',
      )
      ..addFlag(
        'recurse',
        abbr: 'r',
        negatable: false,
        help: 'Encrypt child directories and their files into the security box',
      )
      ..addFlag('debug', abbr: 'd', help: 'Output debug information');
  }

  @override
  String get description => '''
Locks the passed in file by adding it to a security box.
  Generate a Security Box called important.sbox.
    dvault lock path/to/important.txt
  
  Generate the security box in an alternate file/path
    dvault lock --box ~/mysavednotes/important.sbox /path/to/important.txt

  Lock the contents of a directory into a single security box file.
    dvault lock /path/to/encrypt

  Add the contents of a directory and all its children directories and their fiiles
   into a single security box file.
    dvault lock --recurse /path/to/encrypt

  Overwrite the security box if it already exists.
    dvault lock --override  /path/to/important.txt

  ''';

  @override
  String get name => 'lock';

  @override
  Future<void> run() async {
    final overwrite = argResults!['overwrite'] as bool;

    final incudeChildren = argResults!['recurse'] as bool;

    var pathToSecurityBox = argResults!['box'] as String?;

    if (argResults!.rest.isEmpty) {
      printerr(red('You must pass one or more files/directories to lock'));
      print(argParser.usage);
      exit(1);
    }
    final filePaths = argResults!.rest;

    if (pathToSecurityBox == null) {
      if (filePaths.length > 1) {
        printerr(
          red('As you have passed multiple paths you must pass a security box '
              'name via the -v option'),
        );
        print(argParser.usage);
        exit(1);
      }
      final file = filePaths.first;
      // just a single file to lock, derive the security box name
      //from the filename.
      pathToSecurityBox =
          '${join(dirname(file), basenameWithoutExtension(file))}.sbox';
    }

    if (exists(pathToSecurityBox)) {
      if (overwrite) {
        delete(pathToSecurityBox);
      } else {
        printerr(
          red('The passed security box path ${truepath(pathToSecurityBox)} '
              'already exists.'),
        );
        print(argParser.usage);
        exit(1);
      }
    }

    await addSecurityBox(filePaths, pathToSecurityBox,
        incudeChildren: incudeChildren);
  }

  Future<void> addSecurityBox(
    List<String> filePaths,
    String pathToSecurityBox, {
    required bool incudeChildren,
  }) async {
    final securityBox = SecurityBox(pathToSecurityBox);

    for (final filePath in filePaths) {
      if (!exists(filePath)) {
        printerr("The passed path ${truepath(filePath)} doesn't exists.");
        print(argParser.usage);
        exit(1);
      }
      if (isFile(filePath)) {
        securityBox.addFileToIndex(filePath);
      } else if (isDirectory(filePath)) {
        securityBox.addDirectoryToIndex(
          pathToDirectory: filePath,
          recursive: incudeChildren,
        );
      } else {
        print('Skipping $filePath');
      }
    }
    await securityBox.create();
  }
}
