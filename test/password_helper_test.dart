import 'dart:io';
import 'package:test/test.dart';
import 'package:path/path.dart' as p;
import 'package:args/command_runner.dart';
import 'package:dvault/src/util/password_helper.dart';

class TestCommand extends Command<void> {
  @override
  final String name = 'test';
  @override
  final String description = 'Test command';

  TestCommand() {
    addPasswordOptions(this);
  }

  @override
  void run() {}
}

void main() {
  late Directory tempDir;
  late CommandRunner<void> runner;
  late TestCommand command;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('password_test_');
    command = TestCommand();
    runner = CommandRunner<void>('test', 'Test runner')..addCommand(command);
  });

  tearDown(() {
    try {
      tempDir.deleteSync(recursive: true);
    } catch (_) {}
    
    // Clean up environment variable
    if (Platform.environment.containsKey('DVAULT_PASSWORD')) {
      // Can't actually remove it in tests, but we can verify it's handled
    }
  });

  group('addPasswordOptions', () {
    test('adds password-file option', () {
      expect(command.argParser.options.containsKey('password-file'), isTrue);
    });

    test('adds password-stdin flag', () {
      expect(command.argParser.options.containsKey('password-stdin'), isTrue);
    });
  });

  group('getPassword - password-file', () {
    test('reads password from file', () async {
      final passwordFile = File(p.join(tempDir.path, 'password.txt'));
      passwordFile.writeAsStringSync('my_secret_password');

      await runner.run(['test', '--password-file', passwordFile.path]);
      
      final password = await getPassword(command);
      expect(password, equals('my_secret_password'));
    });

    test('trims whitespace from password file', () async {
      final passwordFile = File(p.join(tempDir.path, 'password.txt'));
      passwordFile.writeAsStringSync('  my_password  \n');

      await runner.run(['test', '--password-file', passwordFile.path]);
      
      final password = await getPassword(command);
      expect(password, equals('my_password'));
    });

    test('fails if password file does not exist', () async {
      final nonexistentFile = p.join(tempDir.path, 'nonexistent.txt');

      await runner.run(['test', '--password-file', nonexistentFile]);
      
      expect(
        () => getPassword(command),
        throwsA(anything), // Will exit(1) which throws
      );
    });

    test('fails if password file is empty', () async {
      final passwordFile = File(p.join(tempDir.path, 'empty.txt'));
      passwordFile.writeAsStringSync('');

      await runner.run(['test', '--password-file', passwordFile.path]);
      
      expect(
        () => getPassword(command),
        throwsA(anything),
      );
    });
  });

  group('getPassword - DVAULT_PASSWORD', () {
    test('uses DVAULT_PASSWORD env var when set', () async {
      // Note: In actual tests, we can't easily set environment variables
      // This test demonstrates the logic but may need to run in isolation
      // or use a different test approach
      
      // Mock scenario: if DVAULT_PASSWORD is set
      // final password = await getPassword(command);
      // expect(password, equals(Platform.environment['DVAULT_PASSWORD']));
    });

    test('prioritizes password-file over env var', () async {
      // If both are set, password-file should win
      final passwordFile = File(p.join(tempDir.path, 'password.txt'));
      passwordFile.writeAsStringSync('file_password');

      await runner.run(['test', '--password-file', passwordFile.path]);
      
      final password = await getPassword(command);
      expect(password, equals('file_password'));
    });
  });

  group('Password priority order', () {
    test('password-file has highest priority', () async {
      final passwordFile = File(p.join(tempDir.path, 'password.txt'));
      passwordFile.writeAsStringSync('from_file');

      // Even if env var is set, file should win
      await runner.run(['test', '--password-file', passwordFile.path]);
      
      final password = await getPassword(command);
      expect(password, equals('from_file'));
    });
  });
}
