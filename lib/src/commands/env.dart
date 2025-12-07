import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../util/password_helper.dart';
import '../vfs/io_lockbox.dart';

class EnvCommand extends Command<void> {
  @override
  final String name = 'env';
  @override
  final String description = 'Manage environment variables in the lockbox.';

  EnvCommand() {
    addSubcommand(EnvSetCommand());
    addSubcommand(EnvGetCommand());
    addSubcommand(EnvListCommand());
  }
}

class EnvSetCommand extends Command<void> {
  @override
  final String name = 'set';
  @override
  final String description = 'Set an environment variable.';

  EnvSetCommand() {
    addPasswordOptions(this);
  }

  @override
  void run() async {
    if (argResults!.rest.length < 3) {
      print(red('Usage: dvault env set <lockbox> <key> <value>'));
      exit(1);
    }

    final lockboxPath = argResults!.rest[0];
    final key = argResults!.rest[1];
    final value = argResults!.rest[2];

    if (!exists(lockboxPath)) {
      print(red('Lockbox not found: $lockboxPath'));
      exit(1);
    }

    final password = await getPassPhrase(this);

    try {
      final lockBox = await IOLockBox.open(
        file: File(lockboxPath),
        strongKey: await password,
      );

      await lockBox.setEnv(key, value);
      print(green('Set $key=$value'));

      await lockBox.close();
    } catch (e) {
      print(red('Error: $e'));
      exit(1);
    }
  }
}

class EnvGetCommand extends Command<void> {
  @override
  final String name = 'get';
  @override
  final String description = 'Get an environment variable.';

  EnvGetCommand() {
    addPasswordOptions(this);
  }

  @override
  void run() async {
    if (argResults!.rest.length < 2) {
      print(red('Usage: dvault env get <lockbox_path> <key>'));
      exit(1);
    }

    final lockboxPath = argResults!.rest[0];
    final key = argResults!.rest[1];

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

      final value = repo.getEnv(key);
      if (value != null) {
        print(value);
      } else {
        print(red('Key not found: $key'));
        exit(1);
      }

      await repo.close();
    } catch (e) {
      print(red('Error: $e'));
      exit(1);
    }
  }
}

class EnvListCommand extends Command<void> {
  @override
  final String name = 'list';
  @override
  final String description = 'List all environment variables.';

  EnvListCommand() {
    addPasswordOptions(this);
  }

  @override
  void run() async {
    if (argResults!.rest.isEmpty) {
      print(red('Usage: dvault env list <lockbox_path>'));
      exit(1);
    }

    final lockboxPath = argResults!.rest[0];

    if (!exists(lockboxPath)) {
      print(red('Lockbox  not found: $lockboxPath'));
      exit(1);
    }

    final password = await getPassPhrase(this);

    try {
      final repo = await IOLockBox.open(
        file: File(lockboxPath),
        strongKey: password,
      );

      final envs = repo.listEnv();
      for (final entry in envs.entries) {
        print('${entry.key}=${entry.value}');
      }

      await repo.close();
    } catch (e) {
      print(red('Error: $e'));
      exit(1);
    }
  }
}
