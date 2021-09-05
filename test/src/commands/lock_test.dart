import 'package:dcli/dcli.dart';
import 'package:dvault/src/commands/lock.dart';
import 'package:test/test.dart';
import 'package:args/command_runner.dart';

void main() {
  test('encrypt ...', () async {
    var cmd = CommandRunner('dvault', 'stores encrypted stuff')
      ..addCommand(LockCommand());
    waitForEx(cmd.run(['lock', 'test/data/test_one.txt']));
  });
}