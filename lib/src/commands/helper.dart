/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */


import 'package:dcli/dcli.dart';
import 'package:dvault/src/commands/init.dart';

String askForPassPhrase({String prompt = 'Passphrase'}) {
  const comfirmed = false;
  String passphrase;
  do {
    passphrase = ask(
      '$prompt:',
      hidden: true,
      validator: Ask.lengthMin(InitCommand.minPassPhraseLength),
    );
    final confirm = ask('Confirm $prompt:', hidden: true);

    if (passphrase == confirm) {
      break;
    }

    print("The two phrases didn't match.");
  } while (!comfirmed);
  return passphrase;
}
