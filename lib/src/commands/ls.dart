import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../util/password_helper.dart';
import '../vfs/io_lockbox.dart';

class LsCommand extends Command<void> {
  @override
  final String name = 'ls';
  @override
  final String description = 'List files in the lockbox.';

  LsCommand() {
    argParser.addFlag(
      'recursive',
      abbr: 'r',
      help: 'List recursively',
      defaultsTo: false,
    );
    addPasswordOptions(this);
  }

  @override
  void run() async {
    if (argResults!.rest.isEmpty) {
      print(red('Usage: dvault ls <lockbox_path> [internal_path]'));
      exit(1);
    }

    final lockboxPath = argResults!.rest[0];
    final internalPath =
        argResults!.rest.length > 1 ? argResults!.rest[1] : '/';
    final recursive = argResults!['recursive'] as bool;

    if (!exists(lockboxPath)) {
      print(red('Lockbox not found: $lockboxPath'));
      exit(1);
    }

    final password = await getPassPhrase(this);

    try {
      final repo = await IOLockBox.open(
        file: File(lockboxPath),
        strongKey: password,
      );

      final files = repo.listFiles(internalPath, recursive: recursive);
      for (final file in files) {
        print(file);
      }

      await repo.close();
    } catch (e) {
      print(red('Error: $e'));
      exit(1);
    }
  }
}
