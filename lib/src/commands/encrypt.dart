import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:dvault/src/key_file.dart';
import 'package:encrypt/encrypt.dart';

class EncryptCommand extends Command<void> {
  @override
  String get description => '''Encrypts the passed in file to a vault.
  Generating a vault called important.vault.
    dvault encrypt path/to/important.txt
  
  Generate the vault in an alternate file/path
    dvault encrypt -v ~/mysavednotes/important.vault /path/to/important.txt

  Overwrite the vault if it already exists.
    dvault encrypt -o  /path/to/important.txt

  Encrypt the contents of a directory into a single vault file.
    dvault encrypt /path/to/encrypt

  Recursively encrypt the contents of a directory into a single vault file.
    dvault encrypt -r /path/to/encrypt

  ''';

  @override
  String get name => 'encrypt';

  EncryptCommand() {
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
