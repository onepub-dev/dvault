import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:dvault/src/util/messages.dart';

import '../dot_vault_file.dart';
import 'helper.dart';

class ResetCommand extends Command<void> {
  static int minPassPhraseLength = 12;

  @override
  String get description =>
      '''Reset your passphrase whilst preserving your public/private keys.
  dvault reset''';

  @override
  String get name => 'reset';

  ResetCommand();

  @override
  void run() {
    print(blue('Preparing to reset your passphrase.'));
    print(
        'To protect your keys we lock them with a passphrase with a minimum length of ${ResetCommand.minPassPhraseLength}).');

    String? current;
    do {
      if (current != null) {
        print(red('Invalid passphrase.'));
      }
      current = ask('Current passphrase:', hidden: true);
    } while (!DotVaultFile.load().validatePassphrase(current));

    var newPassphrase = Helper.askForPassPhrase(prompt: 'New passphrase');

    var keyfile = DotVaultFile.load();
    keyfile.resetPassphrase(current: current, newPassphrase: newPassphrase);

    print('');
    print(green('Your passphrase has been reset.'));

    printBackupMessage(DotVaultFile.storagePath);
  }
}
