import 'package:dcli/dcli.dart';
import 'package:dvault/src/commands/init.dart';

class Helper {
  static String askForPassPhrase(String passPhrase) {
    var comfirmed = false;
    do {
      passPhrase = ask('Passphrase:',
          hidden: true,
          validator: Ask.lengthMin(InitCommand.minPassPhraseLength));
      var confirm = ask('Confirm Passphrase:', hidden: true);

      if (passPhrase == confirm) {
        break;
      }

      print("The two phrases didn't match.");
    } while (!comfirmed);
    return passPhrase;
  }
}
