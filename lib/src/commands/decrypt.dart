import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:encrypt/encrypt.dart';

import '../env.dart';
import '../key_file.dart';
import 'helper.dart';

class UnlockCommand extends Command<void> {
  @override
  String get description => '''Decrypts the passed in vault.
  dvault decrypt <vaultname.vault>
  ''';

  @override
  String get name => 'decrypt';

  UnlockCommand() {
    argParser.addOption('vault',
        abbr: 'v', help: 'The path and filename of the vault to decrypt.');
    argParser.addOption('file',
        abbr: 'f', help: '''The path to store the decrypted data in.
    If not specified than the basename of the vault will be used.''');
    argParser.addFlag('overwrite',
        abbr: 'o',
        negatable: false,
        help: 'Overwrites the output if it already exists',
        defaultsTo: false);
    argParser.addFlag('env',
        abbr: 'e',
        negatable: false,
        help:
            'If set the passphrase will be read from the ${Constants.DVAULT_PASSPHRASE} environment variable.');
    argParser.addFlag('debug',
        abbr: 'd', help: 'Output debug information', defaultsTo: false);
  }

  @override
  void run() {
    Settings().setVerbose(enabled: argResults['debug'] as bool);
    var vaultPath = argResults['vault'] as String;

    if (vaultPath == null) {
      printerr("You must pass a 'vault'.");
      print(argParser.usage);
      exit(1);
    }

    if (!exists(vaultPath)) {
      printerr("The passed vault path ${truepath(vaultPath)} doesn't exists.");
      print(argParser.usage);
      exit(1);
    }

    var outputPath = argResults['file'] as String;

    // no output so use the vaultPath after stripping the .vault extension.
    outputPath ??=
        join(dirname(vaultPath), basenameWithoutExtension(vaultPath));

    var overwrite = argResults['overwrite'] as bool;

    if (exists(outputPath)) {
      if (!overwrite) {
        printerr('The output path ${truepath(outputPath)} already exists.');
        print(argParser.usage);
        exit(1);
      }
      delete(outputPath);
    }

    String passPhrase;
    if (argResults['env']) {
      passPhrase = env[Constants.DVAULT_PASSPHRASE];
    } else {
      passPhrase = Helper.askForPassPhrase(passPhrase);
    }
    if (passPhrase.length < 16) {
      printerr(red('The passphrase must be at least 16 characters long.'));
      print(argParser.usage);
      exit(1);
    }

    var keyPair = KeyFile().load(passPhrase);

    var encrypter = Encrypter(RSA(privateKey: keyPair.privateKey));

    var file = File(vaultPath);
    var encrypted = file.readAsBytesSync();
    var contents = encrypter.decryptBytes(Encrypted(encrypted));

    var outputFile = File(outputPath);
    outputFile.writeAsBytesSync(contents);
  }
}
