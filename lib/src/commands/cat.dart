import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../util/password_helper.dart';
import '../vfs/io_lockbox.dart';

class CatCommand extends Command<void> {
  @override
  final String name = 'cat';
  @override
  final String description = 'Print file content to stdout.';

  CatCommand() {
    addPasswordOptions(this);
  }

  @override
  void run() async {
    if (argResults!.rest.length < 2) {
      print(red('Usage: dvault cat <lockbox_path> <file_path>'));
      exit(1);
    }

    final lockboxPath = argResults!.rest[0];
    final filePath = argResults!.rest[1];

    if (!exists(lockboxPath)) {
      print(red('Lockbox not found: $lockboxPath'));
      exit(1);
    }

    final secretKey = await getPassPhrase(this);

    try {
      final lockbox = await IOLockBox.open(
        file: File(lockboxPath),
        strongKey: await secretKey,
      );

      if (!lockbox.exists(filePath)) {
        print(red('File not found in lockbox: $filePath'));
        exit(1);
      }

      final bytes = await lockbox.read(filePath);
      stdout.add(bytes);

      await lockbox.close();
    } catch (e) {
      print(red('Error: $e'));
      exit(1);
    }
  }
}
