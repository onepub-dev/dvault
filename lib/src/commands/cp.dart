import 'dart:io';
import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import '../vfs/io_repository.dart';
import '../util/password_helper.dart';

class CpCommand extends Command<void> {
  @override
  final String name = 'cp';
  @override
  final String description = 'Copy files into or out of the vault.';

  CpCommand() {
    argParser.addFlag('extract', abbr: 'x', help: 'Extract from vault to local', defaultsTo: false);
    addPasswordOptions(this);
  }

  @override
  void run() async {
    if (argResults!.rest.length < 3) {
      print(red('Usage: dvault cp <vault_path> <src> <dest> [--extract]'));
      exit(1);
    }

    final vaultPath = argResults!.rest[0];
    final src = argResults!.rest[1];
    final dest = argResults!.rest[2];
    final extract = argResults!['extract'] as bool;

    if (!exists(vaultPath) && !extract) {
       // If copying IN, vault might not exist, we can create it?
       // For now, assume it must exist or use `create` command first.
       // But `open(create: true)` supports it.
       // Let's allow creating if it doesn't exist.
    }

    final password = await getPassword(this);

    try {
      final repo = await IORepository.open(
        file: File(vaultPath),
        password: password,
        create: !extract && !exists(vaultPath),
      );

      if (extract) {
        // Copy OUT: src is internal, dest is local
        if (!repo.exists(src)) {
          print(red('File not found in vault: $src'));
          exit(1);
        }
        final data = await repo.read(src);
        File(dest).writeAsBytesSync(data);
        print(green('Extracted $src to $dest'));
      } else {
        // Copy IN: src is local, dest is internal
        if (!exists(src)) {
          print(red('Local file not found: $src'));
          exit(1);
        }
        final data = File(src).readAsBytesSync();
        await repo.write(dest, data);
        print(green('Added $src to $dest'));
      }
      
      await repo.close();
    } catch (e) {
      print(red('Error: $e'));
      exit(1);
    }
  }
}
