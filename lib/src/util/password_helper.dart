import 'dart:io';
import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

/// Retrieves the password using the following priority order:
/// 1. --password-file (most secure for automation)
/// 2. --password-stdin (for piping)
/// 3. DVAULT_PASSWORD env var (for testing/CI)
/// 4. Interactive prompt (fallback, most secure for manual use)
Future<String> getPassword(Command<void> command, {bool allowStdin = true}) async {
  final argResults = command.argResults!;
  
  // 1. Check for --password-file
  if (argResults.wasParsed('password-file')) {
    final filePath = argResults['password-file'] as String;
    if (!exists(filePath)) {
      print(red('Password file not found: $filePath'));
      exit(1);
    }
    
    final password = read(filePath).firstLine?.trim();
    if (password == null || password.isEmpty) {
      print(red('Password file is empty: $filePath'));
      exit(1);
    }
    
    return password;
  }
  
  // 2. Check for --password-stdin
  if (allowStdin && argResults.wasParsed('password-stdin') && argResults['password-stdin'] as bool) {
    if (stdin.hasTerminal) {
      print(orange('Warning: --password-stdin specified but no data piped to stdin'));
    }
    
    final password = stdin.readLineSync()?.trim();
    if (password == null || password.isEmpty) {
      print(red('No password provided via stdin'));
      exit(1);
    }
    
    return password;
  }
  
  // 3. Check for DVAULT_PASSWORD env var
  if (Platform.environment.containsKey('DVAULT_PASSWORD')) {
    final password = Platform.environment['DVAULT_PASSWORD']!;
    if (password.isEmpty) {
      print(red('DVAULT_PASSWORD environment variable is empty'));
      exit(1);
    }
    
    return password;
  }
  
  // 4. Fall back to interactive prompt
  return ask('Password:', hidden: true);
}

/// Adds password-related options to a command's argument parser.
void addPasswordOptions(Command<void> command) {
  command.argParser
    ..addOption(
      'password-file',
      abbr: 'f',
      help: 'Read password from file (most secure for automation)',
    )
    ..addFlag(
      'password-stdin',
      help: 'Read password from stdin (for piping)',
      defaultsTo: false,
    );
}
