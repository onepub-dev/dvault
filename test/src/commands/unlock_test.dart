import 'package:dcli/dcli.dart';
import 'package:dvault/src/dot_vault_file.dart';
import 'package:dvault/src/dvault.dart';
import 'package:test/test.dart';

void main() {
  test('decrypt ...', () {
    const passPhrase = 'one and a two and a three';
    env['DVAULT_PASSPHRASE'] = passPhrase;

    /// create a test vault
    ///

    runCommand(
      [
        'decrypt',
        '--env',
        '-v',
        'test/data/test_one.txt.vault',
        '-f',
        'test/data/test_one.txt.result'
      ],
    );

    //  ask('passphrase');
    DotVaultFile.load();
  });
}
