#! /usr/bin/env dshell


import 'package:args/command_runner.dart';
import 'package:dvault/src/commands/create_keys.dart';
import 'package:dvault/src/commands/decrypt.dart';
import 'package:dvault/src/commands/encrypt.dart';

String sshPubKey;
String pemPubKey;

String sshPrivKey;
String pemPrivKey;
String pemPrivKeyClear;

String backupPath;

///
/// Provides a tool to take a complete backup of lastpass and store it
/// into an encrypted zip file.
///
///
void main(List<String> args) {
  var runner = CommandRunner<void>('vault', 'Encrypts/decrypts a file to a "vault" using your ssh keys.');
  runner.addCommand(CreateKeysCommand());
  runner.addCommand(EncryptCommand());
  runner.addCommand(DecryptCommand());

  runner.run(args);
}
