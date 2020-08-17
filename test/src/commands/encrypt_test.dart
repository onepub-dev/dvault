import 'package:dshell/dshell.dart';
import 'package:dvault/src/commands/encrypt.dart';
import 'package:dvault/src/key_file.dart';
import 'package:test/test.dart';
import 'package:args/command_runner.dart';

void main() {
  test('encrypt ...', () async {
    var cmd = CommandRunner('dvault', 'stores encrypted stuff')..addCommand(EncryptCommand());
    waitForEx(cmd.run(['encrypt', '-f', 'test/data/test_one.txt']));
  });
}
