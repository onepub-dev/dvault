import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:epage_file/epage_file.dart';
import 'package:epage_file/src/core/header.dart';
import 'package:epage_file/src/core/page_manager.dart';
import 'package:test/test.dart';

void main() {
  group('EPageFile', () {
    late Directory tempDir;
    late String testFilePath;

    setUp(() {
      tempDir = Directory.systemTemp.createTempSync('epage_file_test_');
      testFilePath = '${tempDir.path}/test.epage';
    });

    tearDown(() {
      tempDir.deleteSync(recursive: true);
    });

    test('create and write to new file', () async {
      final key = SecretKey(List.filled(32, 42));
      final store = await FileBackingStore.open(testFilePath);
      final file = await EPageFile.open(store, key: key);

      final data = Uint8List.fromList('Hello, World!'.codeUnits);
      await file.writeAt(0, data);
      await file.flush();

      final length = await file.length();
      expect(length, equals(data.length));

      await file.close();
    });

    test('write and read data', () async {
      final key = SecretKey(List.filled(32, 42));
      final store = await FileBackingStore.open(testFilePath);
      final file = await EPageFile.open(store, key: key);

      final data = Uint8List.fromList('Hello, World!'.codeUnits);
      await file.writeAt(0, data);
      await file.flush();
      await file.close();

      // Reopen and read
      final store2 = await FileBackingStore.open(testFilePath);
      final file2 = await EPageFile.open(store2, key: key);

      final readData = await file2.readAt(0, data.length);
      expect(readData, equals(data));

      await file2.close();
    });

    test('write across page boundaries', () async {
      final key = SecretKey(List.filled(32, 42));
      final store = await FileBackingStore.open(testFilePath);
      final file = await EPageFile.open(store, key: key);

      // Create data larger than one page (default 4KB)
      final data = Uint8List(8192);
      for (var i = 0; i < data.length; i++) {
        data[i] = i % 256;
      }

      await file.writeAt(0, data);
      await file.flush();
      await file.close();

      // Reopen and verify
      final store2 = await FileBackingStore.open(testFilePath);
      final file2 = await EPageFile.open(store2, key: key);

      final readData = await file2.readAt(0, data.length);
      expect(readData, equals(data));

      await file2.close();
    });

    test('readAt/writeAt without cursor', () async {
      final key = SecretKey(List.filled(32, 42));
      final store = await FileBackingStore.open(testFilePath);
      final file = await EPageFile.open(store, key: key);

      await file.writeAt(0, Uint8List.fromList('Hello'.codeUnits));
      await file.writeAt(5, Uint8List.fromList(', '.codeUnits));
      await file.writeAt(7, Uint8List.fromList('World!'.codeUnits));

      final data = await file.readAt(0, 13);
      expect(String.fromCharCodes(data), equals('Hello, World!'));

      await file.close();
    });

    test('setLength updates pageCount and truncates data', () async {
      final key = SecretKey(List.filled(32, 42));
      final store = await FileBackingStore.open(testFilePath);
      final file = await EPageFile.open(store, key: key);

      final payloadSize = file.pageSize - PageManager.overheadSize;

      // Extend past one page.
      await file.setLength(payloadSize + 500);
      expect(await file.length(), payloadSize + 500);
      await file.flush();

      var headerBytes = (await File(
        testFilePath,
      ).readAsBytes()).sublist(0, EPageFileHeader.headerSize);
      var header = await EPageFileHeader.fromBytes(headerBytes, key);
      expect(header.pageCount, 2);

      final data = Uint8List.fromList(
        List.generate(payloadSize + 200, (i) => i % 256),
      );
      await file.writeAt(0, data);
      await file.flush();

      // Truncate inside the first page.
      await file.setLength(500);
      await file.flush();

      headerBytes = (await File(
        testFilePath,
      ).readAsBytes()).sublist(0, EPageFileHeader.headerSize);
      header = await EPageFileHeader.fromBytes(headerBytes, key);
      expect(header.pageCount, 1);
      expect(await file.length(), 500);

      // Extend again and ensure truncated region is zeroed.
      await file.setLength(payloadSize + 100);
      final extended = await file.readAt(500, 100);
      expect(extended, everyElement(0));

      await file.close();
    });

    test('multi-page write/read/update and encryption', () async {
      final key = SecretKey(List.filled(32, 99));
      final store = await FileBackingStore.open(testFilePath);
      final file = await EPageFile.open(store, key: key);

      final payloadSize = file.pageSize - PageManager.overheadSize;
      final totalLength = payloadSize * 2 + 123;
      final data = Uint8List.fromList(
        List.generate(totalLength, (i) => (i * 7) % 256),
      );

      await file.writeAt(0, data);
      await file.flush();
      await file.close();

      // Reopen and verify full read
      final store2 = await FileBackingStore.open(testFilePath);
      final file2 = await EPageFile.open(store2, key: key);
      final readBack = await file2.readAt(0, totalLength);
      expect(readBack, equals(data));

      // Patch across a page boundary
      final patchStart = payloadSize - 2;
      final patch = Uint8List.fromList('PATCHED_DATA'.codeUnits);
      await file2.writeAt(patchStart, patch);
      await file2.flush();

      final patchedSlice = await file2.readAt(patchStart, patch.length);
      expect(patchedSlice, equals(patch));

      // Ensure ciphertext on disk does not contain the plaintext patch.
      final raw = await File(testFilePath).readAsBytes();
      final rawSlice = raw.sublist(
        EPageFileHeader.headerSize + patchStart,
        EPageFileHeader.headerSize + patchStart + patch.length,
      );
      expect(rawSlice, isNot(equals(patch)));

      await file2.close();
    });
  });
}
