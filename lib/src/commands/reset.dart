import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../key_file.dart';
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

    String current;
    do {
      current = ask('Current passphrase:', hidden: true);
    } while (!KeyFile().validatePassphrase(current));

    var newPassphrase = Helper.askForPassPhrase(prompt: 'New passphrase');

    var keyfile = KeyFile();
    keyfile.resetPassphrase(current: current, newPassphrase: newPassphrase);

    print('');
    print(green('Your passphrase has been reset.'));

    print('');
    print(orange('*' * 80));
    print(orange('*'));
    print(orange(
        '* If you lose your passphrase you will irretrievably lose access to all files protected with DVault'));
    print(orange('*'));
    print(orange('*' * 80));
  }
}
