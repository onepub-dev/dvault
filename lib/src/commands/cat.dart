import 'dart:io';
import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import '../vfs/io_repository.dart';
import '../util/password_helper.dart';

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
      print(red('Usage: dvault cat <vault_path> <file_path>'));
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

      final bytes = await repo.read(filePath);
      stdout.add(bytes);
      
      await repo.close();
    } catch (e) {
      print(red('Error: $e'));
      exit(1);
    }
  }
}
