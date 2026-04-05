import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../util/password_helper.dart';
import '../vfs/io_lockbox.dart';

class CpCommand extends Command<void> {
  @override
  final String name = 'cp';
  @override
  final String description = 'Copy files into or out of the vault.';

  CpCommand() {
    argParser.addFlag(
      'extract',
      abbr: 'x',
      help: 'Extract from vault to local',
      defaultsTo: false,
    );
    addPasswordOptions(this);
  }

  @override
  void run() async {
    if (argResults!.rest.length < 3) {
      print(red('Usage: dvault cp <lockbox_path> <src> <dest> [--extract]'));
      exit(1);
    }

    final lockboxPath = argResults!.rest[0];
    final src = argResults!.rest[1];
    final dest = argResults!.rest[2];
    final extract = argResults!['extract'] as bool;

    if (!exists(lockboxPath) && !extract) {
      // If copying IN, lockbox might not exist, we can create it?
      // For now, assume it must exist or use `create` command first.
      // But `open(create: true)` supports it.
      // Let's allow creating if it doesn't exist.
    }

    final password = await getPassPhrase(this);

    try {
      final lockbox = await IOLockBox.open(
        file: File(lockboxPath),
        strongKey: await password,
        create: !extract && !exists(lockboxPath),
      );

      if (extract) {
        // Copy OUT: src is internal, dest is local
        if (!lockbox.exists(src)) {
          print(red('File not found in lockbox: $src'));
          exit(1);
        }
        final data = await lockbox.read(src);
        File(dest).writeAsBytesSync(data);
        print(green('Extracted $src to $dest'));
      } else {
        // Copy IN: src is local, dest is internal
        if (!exists(src)) {
          print(red('Local file not found: $src'));
          exit(1);
        }
        final data = File(src).readAsBytesSync();
        await lockbox.addFile(dest, data);
        print(green('Added $src to $dest'));
      }

      await lockbox.close();
    } catch (e) {
      print(red('Error: $e'));
      exit(1);
    }
  }
}
