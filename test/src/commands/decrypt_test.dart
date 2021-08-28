import 'package:dcli/dcli.dart';
import 'package:dvault/src/commands/decrypt.dart';
import 'package:dvault/src/key_file.dart';
import 'package:test/test.dart';
import 'package:args/command_runner.dart';

void main() {
  test('decrypt ...', () async {
    var passPhrase = 'one and a two and a three';
    env['DVAULT_PASSPHRASE'] = passPhrase;
    var cmd = CommandRunner('dvault', 'stores encrypted stuff')
      ..addCommand(UnlockCommand());
    waitForEx(cmd.run([
      'decrypt',
      '--env',
      '-v',
      'test/data/test_one.txt.vault',
      '-f',
      'test/data/test_one.txt.result'
    ]));

    //  ask('passphrase');
    KeyFile().load(passPhrase);
  });
}
