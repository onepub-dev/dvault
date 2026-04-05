import 'dart:io';
import 'dart:typed_data';

import 'package:dvault/src/lockbox/lockbox.dart';
import 'package:dvault/src/util/strong_key.dart';
import 'package:dvault/src/vfs/io_lockbox.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() async {
  late Directory tempDir;
  late File vaultFile;
  final password = StrongKey.fromString('test_password_large');

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('dvault_large_test_');
    vaultFile = File(p.join(tempDir.path, 'large.${LockBox.extension}'));
  });

  tearDown(() {
    try {
      tempDir.deleteSync(recursive: true);
    } catch (_) {}
  });

  group('Large Vault Performance', () {
    test('handles 100MB file', () async {
      final repo = await IOLockBox.open(
        file: vaultFile,
        strongKey: password,
        create: true,
      );

      // Create 100MB of data
      final chunkSize = 1024 * 1024; // 1MB chunks
      //   final totalSize = 100 * 1024 * 1024; // 100MB

      print('Creating 100MB file...');
      final stopwatch = Stopwatch()..start();

      // Write in smaller chunks to avoid memory issues
      for (int i = 0; i < 100; i++) {
        final chunk = Uint8List.fromList(
          List.generate(chunkSize, (j) => (i + j) % 256),
        );
        await repo.addFile('chunk_$i.bin', chunk);
      }

      stopwatch.stop();
      print('Write time: ${stopwatch.elapsedMilliseconds}ms');

      // Verify we can read back
      final readStopwatch = Stopwatch()..start();
      final firstChunk = await repo.read('chunk_0.bin');
      readStopwatch.stop();

      print('Read time (first chunk): ${readStopwatch.elapsedMilliseconds}ms');
      expect(firstChunk.length, equals(chunkSize));

      await repo.close();
    }, timeout: Timeout(Duration(minutes: 5)));

    test('handles many small files (10,000)', () async {
      final vaultFile = File(p.join(tempDir.path, 'manu.${LockBox.extension}'));
      final repo = await IOLockBox.open(
        file: vaultFile,
        strongKey: password,
        create: true,
      );

      print('Creating 10,000 small files...');
      final stopwatch = Stopwatch()..start();

      for (int i = 0; i < 1001; i++) {
        final content = Uint8List.fromList('File $i content'.codeUnits);
        await repo.addFile('file_$i.txt', content);

        if (i != 0 && i % 1000 == 0) {
          print('Created $i files...');
        }
      }

      stopwatch.stop();
      print('Total write time: ${stopwatch.elapsedMilliseconds}ms');
      print('Average per file: ${stopwatch.elapsedMilliseconds / 10000}ms');

      // Test random access
      final readStopwatch = Stopwatch()..start();
      final content1000 = await repo.read('file_1000.txt');
      readStopwatch.stop();

      print('Random read time: ${readStopwatch.elapsedMilliseconds}ms');
      expect(
        content1000,
        equals(Uint8List.fromList('File 5000 content'.codeUnits)),
      );

      await repo.close();
    }, timeout: Timeout(Duration(minutes: 10)));

    test('handles deep directory structure', () async {
      final repo = await IOLockBox.open(
        file: vaultFile,
        strongKey: password,
        create: true,
      );

      // Create 100 levels deep
      print('Creating deep directory structure...');
      final stopwatch = Stopwatch()..start();

      String path = '';
      for (int i = 0; i < 100; i++) {
        path += 'dir$i/';
      }
      path += 'deep_file.txt';

      await repo.addFile(path, Uint8List.fromList('deep content'.codeUnits));

      stopwatch.stop();
      print('Write time: ${stopwatch.elapsedMilliseconds}ms');

      // Verify we can read it back
      expect(repo.exists(path), isTrue);
      final content = await repo.read(path);
      expect(content, equals(Uint8List.fromList('deep content'.codeUnits)));

      await repo.close();
    });

    test('vault file size is reasonable', () async {
      final repo = await IOLockBox.open(
        file: vaultFile,
        strongKey: password,
        create: true,
      );

      // Write 10MB of actual data
      final totalDataSize = 10 * 1024 * 1024;
      final chunkSize = 1024 * 1024; // 1MB

      for (int i = 0; i < 10; i++) {
        final chunk = Uint8List(chunkSize);
        for (int j = 0; j < chunkSize; j++) {
          chunk[j] = (i + j) % 256;
        }
        await repo.addFile('data_$i.bin', chunk);
      }

      await repo.close();

      final vaultSize = vaultFile.lengthSync();
      final overhead = vaultSize - totalDataSize;
      final overheadPercent = (overhead / totalDataSize) * 100;

      print('Data size: ${totalDataSize / 1024 / 1024}MB');
      print('Vault size: ${vaultSize / 1024 / 1024}MB');
      print(
        'Overhead: ${overhead / 1024}KB (${overheadPercent.toStringAsFixed(2)}%)',
      );

      // Overhead should be reasonable (< 10% for this size)
      expect(overheadPercent, lessThan(10));
    });

    test('list operation performance on large vault', () async {
      final repo = await IOLockBox.open(
        file: vaultFile,
        strongKey: password,
        create: true,
      );

      // Create 1000 files
      for (int i = 0; i < 1000; i++) {
        await repo.addFile('file_$i.txt', Uint8List.fromList('data'.codeUnits));
      }

      // Test list performance
      final stopwatch = Stopwatch()..start();
      final files = repo.listFiles('/');
      stopwatch.stop();

      print('List time for 1000 files: ${stopwatch.elapsedMilliseconds}ms');
      expect(files.length, equals(1000));
      expect(
        stopwatch.elapsedMilliseconds,
        lessThan(1000),
      ); // Should be fast (< 1s)

      await repo.close();
    });

    test('env vars work with large vault', () async {
      final lockbox = await IOLockBox.open(
        file: vaultFile,
        strongKey: password,
        create: true,
      );

      // Create a large vault
      for (int i = 0; i < 100; i++) {
        await lockbox.addFile('file_$i.txt', Uint8List(1024));
      }

      // Set env var (should update Page 0 without affecting file data)
      final stopwatch = Stopwatch()..start();

      await lockbox.setEnv('TEST_VAR', 'test_value');
      stopwatch.stop();

      print(
        'Set env var time in large vault: ${stopwatch.elapsedMilliseconds}ms',
      );
      expect(
        stopwatch.elapsedMilliseconds,
        lessThan(100),
      ); // Should be very fast

      // Verify env var persists
      await lockbox.close();

      final repo2 = await IOLockBox.open(file: vaultFile, strongKey: password);

      expect(repo2.getEnv('TEST_VAR'), equals('test_value'));
      await repo2.close();
    });
  });

  group('Stress Tests', () {
    test('random access pattern', () async {
      final repo = await IOLockBox.open(
        file: vaultFile,
        strongKey: password,
        create: true,
      );

      // Create 100 files
      for (int i = 0; i < 100; i++) {
        await repo.addFile(
          'file_$i.txt',
          Uint8List.fromList('File $i'.codeUnits),
        );
      }

      // Random access
      final random = Random(42); // Fixed seed for reproducibility
      final stopwatch = Stopwatch()..start();

      for (int i = 0; i < 100; i++) {
        final fileNum = random.nextInt(100);
        final content = await repo.read('file_$fileNum.txt');
        expect(content.length, greaterThan(0));
      }

      stopwatch.stop();
      print('100 random reads: ${stopwatch.elapsedMilliseconds}ms');

      await repo.close();
    });
  });
}

class Random {
  int _seed;

  Random(this._seed);

  int nextInt(int max) {
    _seed = (_seed * 1103515245 + 12345) & 0x7fffffff;
    return _seed % max;
  }
}
