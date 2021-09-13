import 'package:dcli/dcli.dart';
import 'package:dvault/src/dot_vault_file.dart';
import 'package:dvault/src/dvault.dart';
import 'package:dvault/src/rsa/rsa_generator.dart';
import 'package:dvault/src/util/exceptions.dart';
import 'package:test/test.dart';

void main() {
  test('create keys ...', () {
    const passPhrase = 'one and a two and a three';
    env['DVAULT_PASSPHRASE'] = passPhrase;
    runCommand(['init', '--env']);

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
