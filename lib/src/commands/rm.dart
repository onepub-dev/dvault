import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../util/password_helper.dart';
import '../vfs/io_lockbox.dart';

class RmCommand extends Command<void> {
  @override
  final String name = 'rm';
  @override
  final String description = 'Remove files from the lockbox.';

  RmCommand() {
    addPasswordOptions(this);
  }

  @override
  void run() async {
    if (argResults!.rest.length < 2) {
      print(red('Usage: dvault rm <lockbox_path> <file_path>'));
      exit(1);
    }

    final lockboxPath = argResults!.rest[0];
    final filePath = argResults!.rest[1];

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

      if (!repo.exists(filePath)) {
        print(red('File not found in lockbox: $filePath'));
        exit(1);
      }

      await repo.delete(filePath);
      print(green('Removed $filePath'));

      await repo.close();
    } catch (e) {
      print(red('Error: $e'));
      exit(1);
    }
  }
}
