/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:dvault/src/util/strong_key.dart';

import '../dot_vault_file.dart';
import '../util/messages.dart';
import 'helper.dart';

class ResetCommand extends Command<void> {
  static int minPassPhraseLength = 12;

  ResetCommand();

  @override
  String get description => '''
  Reset your passphrase whilst preserving your public/private keys.
  dvault reset''';

  @override
  String get name => 'reset';

  @override
  void run() async {
    print(blue('Preparing to reset your passphrase.'));
    print(
      'To protect your keys we lock them with a passphrase with a '
      'minimum length of ${ResetCommand.minPassPhraseLength}).',
    );

    StrongKey? current;
    do {
      if (current != null) {
        print(red('Invalid passphrase.'));
      }
      current = await askForPassPhrase(prompt: 'Current passphrase:');
    } while (!DotVaultFile.load().validatePassphrase(current));

    final newPassphrase = await askForPassPhrase(prompt: 'New passphrase');

    DotVaultFile.load().resetPassphrase(
      current: current,
      newPassphrase: newPassphrase,
    );

    print('');
    print(green('Your passphrase has been reset.'));

    printBackupMessage(DotVaultFile.storagePath);
  }
}
