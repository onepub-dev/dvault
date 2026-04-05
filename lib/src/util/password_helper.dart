import 'dart:io';
import 'dart:typed_data';

import 'package:args/command_runner.dart';
import 'package:args/src/arg_results.dart';
import 'package:dcli/dcli.dart';
import 'package:dvault/src/commands/init.dart';
import 'package:dvault/src/util/ask.dart';
import 'package:dvault/src/util/strong_key.dart';

/// Retrieves the password using the following priority order:
/// 1. --passphrase-file (most secure for automation)
/// 2. --passphrase-stdin (for piping)
/// 3. DVAULT_PASSWORD env var (for testing/CI)
/// 4. Interactive prompt (fallback, most secure for manual use)
Future<StrongKey> getPassPhrase(
  Command<void> command, {
  bool allowStdin = true,
}) async {
  final argResults = command.argResults!;

  // 1. Check for --passphrase-file
  if (argResults.wasParsed('passphrase-file')) {
    return _readPassPhraseFile(argResults);
  }

  // 2. Check for --passphrase-stdin
  if (allowStdin &&
      argResults.wasParsed('passphrase-stdin') &&
      argResults['passphrase-stdin'] as bool) {
    return _readPassPhraseFromStdin();
  }

  // 3. Check for DVAULT_PASSWORD env var
  if (argResults.wasParsed('env') &&
      Platform.environment.containsKey(InitCommand.DVAULT_PASSPHRASE)) {
    final password = Platform.environment[InitCommand.DVAULT_PASSPHRASE]!;
    if (password.isEmpty) {
      print(
        red('${InitCommand.DVAULT_PASSPHRASE} environment variable is empty'),
      );
      exit(1);
    }

    return StrongKey.fromString(password);
  }

  // 4. Fall back to interactive prompt
  return askForPassword('Password:');
}

Future<StrongKey> _readPassPhraseFromStdin() async {
  if (stdin.hasTerminal) {
    print(
      orange(
        'Warning: --passphrase-stdin specified but no data piped to stdin',
      ),
    );
  }

  final password = Uint8List(255);
  int length = 0;
  int char;
  do {
    char = stdin.readByteSync();
    if (char != 10) {
      password.add(char);
      length++;
    }
    if (length == 255) {
      print(
        orange('Warning: passphrase exceeded 255 character limit, truncated'),
      );
      break;
    }
  } while (char != 10);

  if (length == 0) {
    print(red('No passphrase provided via stdin'));
    exit(1);
  }

  return await StrongKey.fromPassPhrase(password);
}

Future<StrongKey> _readPassPhraseFile(ArgResults argResults) async {
  final filePath = argResults['passphrase-file'] as String;
  if (!exists(filePath)) {
    print(red('Passphrase file not found: $filePath'));
    exit(1);
  }

  final password = _trim(File(filePath).readAsBytesSync());

  if (password.length == 0) {
    print(red('Passphrase file is empty: $filePath'));
    exit(1);
  }

  return StrongKey.fromPassPhrase(password);
}

Uint8List _trim(Uint8List password) {
  int end = password.length;

  // Trim trailing whitespace/newline characters
  while (end > 0 &&
      (password[end - 1] == 10 || // LF
          password[end - 1] == 13 || // CR
          password[end - 1] == 32 || // Space
          password[end - 1] == 9)) {
    // Tab
    end--;
  }

  // trim leading whitespace/newline characters
  int start = 0;
  while (start < end &&
      (password[start] == 10 || // LF
          password[start] == 13 || // CR
          password[start] == 32 || // Space
          password[start] == 9)) {
    // Tab
    start++;
  }
  return password.sublist(start, end);
}

/// Adds passphrase-related options to a command's argument parser.
void addPasswordOptions(Command<void> command) {
  command.argParser
    ..addOption(
      'passphrase-file',
      abbr: 'f',
      help: 'Read password from file (most secure for automation)',
    )
    ..addFlag(
      'passphrase-stdin',
      help: 'Read password from stdin (for piping)',
      defaultsTo: false,
    )
    ..addFlag(
      'env',
      help:
          'Read password the ${InitCommand.DVAULT_PASSPHRASE} environment variable - insecure for production use!!',
      defaultsTo: false,
    );
}
