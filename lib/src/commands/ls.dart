import 'dart:io';
import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import '../vfs/io_repository.dart';
import '../util/password_helper.dart';

class LsCommand extends Command<void> {
  @override
  final String name = 'ls';
  @override
  final String description = 'List files in the vault.';

  LsCommand() {
    argParser.addFlag('recursive', abbr: 'R', help: 'List recursively', defaultsTo: false);
    addPasswordOptions(this);
  }

  @override
  void run() async {
    if (argResults!.rest.isEmpty) {
      print(red('Usage: dvault ls <vault_path> [internal_path]'));
      exit(1);
    }

    final vaultPath = argResults!.rest[0];
    final internalPath = argResults!.rest.length > 1 ? argResults!.rest[1] : '/';
    final recursive = argResults!['recursive'] as bool;

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

      final files = repo.list(internalPath, recursive: recursive);
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
