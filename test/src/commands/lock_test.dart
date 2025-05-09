/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dcli/dcli.dart';
import 'package:dcli_core/dcli_core.dart' as core;
import 'package:dvault/src/dvault.dart';
import 'package:test/test.dart';

void main() {
  test('encrypt ...', () async {
    const content = 'abc123';
    await core.withTempFile((pathToTestFile) async {
      pathToTestFile.append(content);
      await core.withTempFile((pathToSecuritBox) async {
        await core.withTempFile((pathToResult) async {
          await runCommand(['lock', '--box', pathToSecuritBox, pathToTestFile]);

          // await withEnvironment(() async {
          //   await runCommand([
          //     'unlock',
          //     '--box',
          //     pathToSecuritBox,
          //     '--env',
          //     testPassPhrase,
          //     '--to',
          //     pathToResult
          //   ]);
          // }, environment: {Constants.dvaultPassphraseEnvKey: testPassPhrase});
        }, create: false);
      }, create: false);
    }, create: false);
  });
}
