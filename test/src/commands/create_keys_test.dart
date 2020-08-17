import 'package:dshell/dshell.dart';
import 'package:dvault/src/commands/create_keys.dart';
import 'package:dvault/src/key_file.dart';
import 'package:test/test.dart';
import 'package:args/command_runner.dart';

void main() {
  test('create keys ...', () async {
    var passPhrase = 'one and a two and a three';
    setEnv('DVAULT_PASSPHRASE', passPhrase);
    var cmd = CommandRunner('dvault', 'creates keys')..addCommand(CreateKeysCommand());
    waitForEx(cmd.run(['create', '--env']));

    //  ask('pass phrase');
    KeyFile().load(passPhrase);
  });
}
