import 'package:args/command_runner.dart';

import 'commands/init.dart';
import 'commands/lock.dart';
import 'commands/reset.dart';
import 'commands/unlock.dart';

void runCommand(List<String> args) {
  final runner = CommandRunner<void>(
    'vault',
    'Locks/Unlocks a file by encrypting it into a transportable "vault".',
  );
  runner.addCommand(InitCommand());
  runner.addCommand(LockCommand());
  runner.addCommand(UnlockCommand());

  runner.addCommand(ResetCommand());
  runner.run(args);
}
