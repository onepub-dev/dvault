/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dcli/dcli.dart';
import 'package:dvault/src/dot_vault_file.dart';
import 'package:dvault/src/dvault.dart';
import 'package:dvault/src/rsa/rsa_generator.dart';
import 'package:dvault/src/util/exceptions.dart';
import 'package:test/test.dart';

void main() {
  test('create keys ...', () async {
    const passPhrase = 'one and a two and a three';
    env['DVAULT_PASSPHRASE'] = passPhrase;
    await runCommand(['init', '--env']);

    print('Generating key pair. be patient');
    final pair = RSAGenerator().generateKeyPair();

    print('saving file');
    DotVaultFile.create(pair.privateKey, pair.publicKey, passPhrase);

    print('loading file');
    //  ask('passphrase');
    DotVaultFile.load();
  });

  test('Invalid passphrase ...', () {
    const passPhrase = 'one and a two and a three';
    env['DVAULT_PASSPHRASE'] = passPhrase;

    expect(
      () => DotVaultFile.load().privateKey(passphrase: '${passPhrase}bad'),
      throwsA(const TypeMatcher<InvalidPassphraseException>()),
    );
  });
}
