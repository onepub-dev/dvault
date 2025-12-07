/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dvault/src/util/ask.dart';
import 'package:dvault/src/util/strong_key.dart';

Future<StrongKey> askForPassPhrase({String prompt = 'Passphrase'}) async {
  const comfirmed = false;
  StrongKey passphrase;
  do {
    passphrase = await askForPassword('$prompt:');
    final confirm = await askForPassword('Confirm $prompt:');

    if (passphrase == confirm) {
      break;
    }

    print("The two phrases didn't match.");
  } while (!comfirmed);
  return passphrase;
}
