import 'package:dcli/dcli.dart';
import 'package:dvault/src/commands/init.dart';
import 'package:dvault/src/key_file.dart';
import 'package:dvault/src/util/generator.dart';
import 'package:encrypt/encrypt.dart';
import 'package:test/test.dart';
import 'package:args/command_runner.dart';

void main() {
  test('create keys ...', () async {
    var passPhrase = 'one and a two and a three';
    env['DVAULT_PASSPHRASE'] = passPhrase;
    var cmd = CommandRunner('dvault', 'creates keys')
      ..addCommand(InitCommand());
    await cmd.run(['init', '--env']);

    var pair = Generator().generateKeyPair();

    KeyFile().simple(
        pair.privateKey, pair.publicKey, 'A test password', IV.fromLength(16));

    //  ask('passphrase');
    KeyFile().load(passPhrase);
  });
}
