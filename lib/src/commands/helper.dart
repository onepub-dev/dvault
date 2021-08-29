import 'package:dcli/dcli.dart';
import 'package:dvault/src/commands/init.dart';

class Helper {
  static String askForPassPhrase({String prompt = 'Passphrase'}) {
    var comfirmed = false;
    String passphrase;
    do {
      passphrase = ask('$prompt:',
          hidden: true,
          validator: Ask.lengthMin(InitCommand.minPassPhraseLength));
      var confirm = ask('Confirm $prompt:', hidden: true);

      if (passphrase == confirm) {
        break;
      }

      print("The two phrases didn't match.");
    } while (!comfirmed);
    return passphrase;
  }
}
