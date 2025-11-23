import 'dart:io';
import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import '../vfs/io_repository.dart';
import '../util/password_helper.dart';

class MvCommand extends Command<void> {
  @override
  final String name = 'mv';
  @override
  final String description = 'Move or rename files within the vault.';

  MvCommand() {
    addPasswordOptions(this);
  }

  @override
  void run() async {
    if (argResults!.rest.length < 3) {
      print(red('Usage: dvault mv <vault_path> <old_path> <new_path>'));
      exit(1);
    }

    final vaultPath = argResults!.rest[0];
    final oldPath = argResults!.rest[1];
    final newPath = argResults!.rest[2];

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

      if (!repo.exists(oldPath)) {
        print(red('File not found in vault: $oldPath'));
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
