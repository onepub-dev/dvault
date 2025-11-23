import 'dart:io';
import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import '../vfs/io_repository.dart';
import '../util/password_helper.dart';

class EnvCommand extends Command<void> {
  @override
  final String name = 'env';
  @override
  final String description = 'Manage environment variables in the vault.';

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
      print(red('Usage: dvault env set <vault_path> <key> <value>'));
      exit(1);
    }

    final vaultPath = argResults!.rest[0];
    final key = argResults!.rest[1];
    final value = argResults!.rest[2];

    if (!exists(vaultPath)) {
      print(red('Vault not found: $vaultPath'));
      exit(1);
    }

    final password = await getPassword(this);

    try {
      final repo = await IORepository.open(
        file: File(vaultPath),
        password: password,
      );

      await repo.setEnv(key, value);
      print(green('Set $key=$value'));
      
      await repo.close();
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
      print(red('Usage: dvault env get <vault_path> <key>'));
      exit(1);
    }

    final vaultPath = argResults!.rest[0];
    final key = argResults!.rest[1];

    if (!exists(vaultPath)) {
      print(red('Vault not found: $vaultPath'));
      exit(1);
    }

    final password = await getPassword(this);

    try {
      final repo = await IORepository.open(
        file: File(vaultPath),
        password: password,
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
      print(red('Usage: dvault env list <vault_path>'));
      exit(1);
    }

    final vaultPath = argResults!.rest[0];

    if (!exists(vaultPath)) {
      print(red('Vault not found: $vaultPath'));
      exit(1);
    }

    final password = await getPassword(this);

    try {
      final repo = await IORepository.open(
        file: File(vaultPath),
        password: password,
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
