import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../lockbox/lockbox_format.dart';
import '../util/password_helper.dart';
import '../vfs/io_lockbox.dart';

class InitCommand extends Command<void> {
  @override
  final String name = 'init';
  @override
  final String description = 'Initialize a new lockbox.';

  InitCommand() {
    argParser.addOption(
      'page-size',
      abbr: 'p',
      help: 'Page size in bytes (default: 64KB)',
      defaultsTo: LockboxFormat.defaultPageSize.toString(),
    );
    addPasswordOptions(this);
  }

  static int get minPassPhraseLength => 12;

  @override
  void run() async {
    if (argResults!.rest.isEmpty) {
      print(
        red(
          'Usage: dvault init <lockbox_path> [--page-size <bytes>] [--password-file <file>]',
        ),
      );
      exit(1);
    }

    final lockboxPath = argResults!.rest[0];
    final pageSizeStr = argResults!['page-size'] as String;
    final pageSize = int.tryParse(pageSizeStr);

    if (pageSize == null || pageSize <= 0) {
      print(red('Invalid page size: $pageSizeStr'));
      exit(1);
    }

    if (exists(lockboxPath)) {
      print(red('Lockbox already exists: $lockboxPath'));
      exit(1);
    }

    // Get password using helper
    final isInteractive =
        !argResults!.wasParsed('password-file') &&
        !argResults!.wasParsed('password-stdin') &&
        !Platform.environment.containsKey('DVAULT_PASSWORD');

    String password;
    if (isInteractive) {
      password = ask('Password:', hidden: true);
      final confirm = ask('Confirm Password:', hidden: true);

      if (password != confirm) {
        print(red('Passwords do not match.'));
        exit(1);
      }
    } else {
      password = await getPassword(this);
    }

    try {
      final repo = await IOLockbox.open(
        file: File(lockboxPath),
        password: password,
        create: true,
        pageSize: pageSize,
      );

      await repo.close();
      print(
        green(
          'Lockbox initialized at $lockboxPath with page size $pageSize bytes.',
        ),
      );
    } catch (e) {
      print(red('Error: $e'));
      exit(1);
    }
  }
}
