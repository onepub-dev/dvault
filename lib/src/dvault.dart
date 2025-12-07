/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:args/command_runner.dart';

import 'commands/cat.dart';
import 'commands/cp.dart';
import 'commands/env.dart';
import 'commands/init.dart';
import 'commands/lock.dart';
import 'commands/ls.dart';
import 'commands/mv.dart';
import 'commands/reset.dart';
import 'commands/rm.dart';
import 'commands/unlock.dart';

Future<void> runCommand(List<String> args) async {
  final runner =
      CommandRunner<void>(
          'dvault',
          'Locks/Unlocks a file or directory by encrypting it into a transportable "security box".',
        )
        ..addCommand(InitCommand())
        ..addCommand(LsCommand())
        ..addCommand(CatCommand())
        ..addCommand(CpCommand())
        ..addCommand(RmCommand())
        ..addCommand(MvCommand())
        ..addCommand(EnvCommand())
        ..addCommand(LockCommand())
        ..addCommand(UnlockCommand())
        ..addCommand(ResetCommand());
  await runner.run(args);
}
