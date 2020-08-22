import 'package:dcli/dcli.dart';

class Helper {
  static String askForPassPhrase(String passPhrase) {
    var comfirmed = false;
    do {
      passPhrase = ask('Pass Phrase:', hidden: true, validator: AskMinLength(12));
      var confirm = ask('Confirm Pass Phrase:', hidden: true);

      if (passPhrase == confirm) {
        break;
      }

      print("The two phrases didn't match.");
    } while (!comfirmed);
    return passPhrase;
  }
}
