import 'package:dcli/dcli.dart';
import 'package:dvault/src/commands/init.dart';
import 'package:dvault/src/key_file.dart';
import 'package:dvault/src/util/exceptions.dart';
import 'package:dvault/src/util/generator.dart';
import 'package:test/test.dart';
import 'package:args/command_runner.dart';

void main() {
  test('create keys ...', () async {
    var passPhrase = 'one and a two and a three';
    env['DVAULT_PASSPHRASE'] = passPhrase;
    var cmd = CommandRunner('dvault', 'creates keys')
      ..addCommand(InitCommand());
    await cmd.run(['init', '--env']);

    print('Generating key pair. be patient');
    var pair = Generator().generateKeyPair();

    print('saving file');
    KeyFile().save(pair.privateKey, pair.publicKey, passPhrase);

    print('loading file');
    //  ask('passphrase');
    KeyFile().load(passPhrase);
  });

  test('Invalid passphrase ...', () async {
    var passPhrase = 'one and a two and a three';
    env['DVAULT_PASSPHRASE'] = passPhrase;

    expect(() => KeyFile().load(passPhrase + 'bad'),
        throwsA(TypeMatcher<InvalidPassphraseException>()));
  });
}
