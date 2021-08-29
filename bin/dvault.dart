#! /usr/bin/env dcli

import 'package:args/command_runner.dart';
import 'package:dvault/src/commands/init.dart';
import 'package:dvault/src/commands/decrypt.dart';
import 'package:dvault/src/commands/encrypt.dart';
import 'package:dvault/src/commands/reset.dart';

String? sshPubKey;
String? pemPubKey;

String? sshPrivKey;
String? pemPrivKey;
String? pemPrivKeyClear;

String? backupPath;

///
/// Provides a tool to take a complete backup of lastpass and store it
/// into an encrypted zip file.
///
///
void main(List<String> args) {
  var runner = CommandRunner<void>('vault',
      'Locks/Unlocks a file by encrypting it to a transportable "vault".');
  runner.addCommand(InitCommand());
  runner.addCommand(LockCommand());
  runner.addCommand(UnlockCommand());

  runner.addCommand(ResetCommand());
  runner.run(args);
}
