import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../util/password_helper.dart';
import '../vfs/io_lockbox.dart';

class MvCommand extends Command<void> {
  @override
  final String name = 'mv';
  @override
  final String description = 'Move or rename files within the lockbox.';

  MvCommand() {
    addPasswordOptions(this);
  }

  @override
  void run() async {
    if (argResults!.rest.length < 3) {
      print(red('Usage: dvault mv <lockbox_path> <old_path> <new_path>'));
      exit(1);
    }

    final pathToLockbox = argResults!.rest[0];
    final oldPath = argResults!.rest[1];
    final newPath = argResults!.rest[2];

    if (!exists(pathToLockbox)) {
      print(red('Lockbox not found: $pathToLockbox'));
      exit(1);
    }

    final password = await getPassPhrase(this);

    try {
      final repo = await IOLockBox.open(
        file: File(pathToLockbox),
        strongKey: password,
      );

      if (!repo.exists(oldPath)) {
        print(red('File not found in lockbox: $oldPath'));
        exit(1);
      }

      if (repo.exists(newPath)) {
        print(red('Destination already exists: $newPath'));
        exit(1);
      }

      await repo.rename(oldPath, newPath);
      print(green('Moved $oldPath to $newPath'));

      await repo.close();
    } catch (e) {
      print(red('Error: $e'));
      exit(1);
    }
  }
}
