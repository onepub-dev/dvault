import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dshell/dshell.dart';
import 'package:dvault/src/key_file.dart';
import 'package:dvault/src/vault.dart';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/pointycastle.dart';

class EncryptCommand extends Command<void> {
  @override
  String get description => '''Encrypts the passed in file to a vault.
  vault encrypt -f <pathname to encrypt> -v <pathname of resulting vault>''';

  @override
  String get name => 'encrypt';

  EncryptCommand() {
    argParser.addOption('file', abbr: 'f', help: 'The path to the file that is to be encrypted.');
    argParser.addOption('vault', abbr: 'v', help: '''The path and filename to store the encrypted file into.
    If you don't pass a vault then the [file] name will be used with a .vault extension''');
    argParser.addFlag('overwrite',
        abbr: 'o', negatable: false, help: 'Overwrites the vault if it already exists', defaultsTo: false);
    argParser.addFlag('debug', abbr: 'd', help: 'Output debug information', defaultsTo: false);
  }

  @override
  void run() {
    Settings().setVerbose(enabled: true);
    var overwrite = argResults['overwrite'] as bool;

    var filePath = argResults['file'] as String;

    if (!exists(filePath)) {
      printerr("The passed file path ${truepath(filePath)} doesn't exists.");
      print(argParser.usage);
      exit(1);
    }

    var vaultPath = argResults['vault'] as String;

    if (vaultPath != null && exists(vaultPath)) {
      if (overwrite) {
        delete(vaultPath);
      } else {
        printerr('The passed vault path ${truepath(vaultPath)} already exists.');
        print(argParser.usage);
        exit(1);
      }
    }

    /// if there is no vault path generate the default.
    vaultPath ??= '$filePath.vault';

    var publicKey = KeyFile().loadPublic();

    var encrypter = Encrypter(RSA(publicKey: publicKey));

    var file = File(filePath);
    var contents = file.readAsBytesSync();
    var encrypted = encrypter.encryptBytes(contents);

    var vault = File(vaultPath);
    vault.writeAsBytesSync(encrypted.bytes);
  }
}
