import 'dart:io';
import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import '../vfs/io_repository.dart';
import '../util/password_helper.dart';

class RmCommand extends Command<void> {
  @override
  final String name = 'rm';
  @override
  final String description = 'Remove files from the vault.';

  RmCommand() {
    addPasswordOptions(this);
  }

  @override
  void run() async {
    if (argResults!.rest.length < 2) {
      print(red('Usage: dvault rm <vault_path> <file_path>'));
      exit(1);
    }

    final vaultPath = argResults!.rest[0];
    final filePath = argResults!.rest[1];

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

      if (!repo.exists(filePath)) {
        print(red('File not found in vault: $filePath'));
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
