import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:dvault/src/dot_vault_file.dart';
import 'package:dvault/src/rsa/rsa_generator.dart';
import 'package:dvault/src/util/ask.dart';
import 'package:dvault/src/util/strong_key.dart';
import 'package:strings/strings.dart';

import '../util/password_helper.dart';

class InitCommand extends Command<void> {
  static const DVAULT_PASSPHRASE = 'DVAULT_PASSPHRASE';
  @override
  final String name = 'init';
  @override
  final String description =
      'Initialize dvault by creating a public/private key pair.';

  InitCommand() {
    addPasswordOptions(this);
  }

  static int get minPassPhraseLength => 12;

  @override
  void run() async {
    if (argResults!.rest.isEmpty) {
      print(red('Usage: dvault init [--passphrase-file <file>]'));
      exit(1);
    }

    final lockboxPath = argResults!.rest[0];

    if (exists(lockboxPath)) {
      print(red('Lockbox already exists: $lockboxPath'));
      exit(1);
    }

    if (argResults!.wasParsed('env')) {
      if (Strings.isBlank(Platform.environment[DVAULT_PASSPHRASE])) {
        printerr(red('$DVAULT_PASSPHRASE environment variable is not set'));
        exit(1);
      }
    }
    // Get password using helper
    final isInteractive =
        !argResults!.wasParsed('passphrase-file') &&
        !argResults!.wasParsed('passphrase-stdin') &&
        !argResults!.wasParsed('env');

    StrongKey strongKey;
    if (isInteractive) {
      strongKey = await askForPassword('Passphrase:');
      final confirm = await askForPassword('Confirm Passphrase:');

      if (strongKey != confirm) {
        print(red('Passwords do not match.'));
        exit(1);
      }
    } else {
      strongKey = await getPassPhrase(this);
    }

    try {
      print(green('Generating key pair, be patient...'));
      final pair = RSAGenerator().generateKeyPair();

      DotVaultFile.create(pair.privateKey, pair.publicKey, strongKey);
      print(green('Saved keys to ${DotVaultFile.storagePath}'));
    } catch (e) {
      print(red('Error: $e'));
      exit(1);
    }
  }
}
