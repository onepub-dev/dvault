import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:epage_file/epage_file.dart';
import 'package:epage_file/src/core/header.dart';
import 'package:test/test.dart';

void main() {
  test('header encodes/decodes and data survives reopen', () async {
    final tempDir = Directory.systemTemp.createTempSync('epage_debug_');
    final testFilePath = '${tempDir.path}/test.epage';

    try {
      final key = SecretKey(List.filled(32, 42));
      final store = await FileBackingStore.open(testFilePath);
      final file = await EPageFile.open(store, key: key);

      final data = Uint8List.fromList('Hello, World!'.codeUnits);
      await file.writeAt(0, data);
      await file.flush();
      await file.close();

      final rawBytes = await File(testFilePath).readAsBytes();
      final headerBytes = rawBytes.sublist(0, EPageFileHeader.headerSize);
      final header = await EPageFileHeader.fromBytes(headerBytes, key);

      expect(header.version, equals(EPageFileHeader.currentVersion));
      expect(header.pageSize, equals(EPageFile.defaultPageSize));
      expect(header.logicalLength, equals(data.length));
      expect(header.pageCount, equals(1));

      final store2 = await FileBackingStore.open(testFilePath);
      final file2 = await EPageFile.open(store2, key: key);
      final readData = await file2.readAt(0, data.length);
      expect(readData, equals(data));
      await file2.close();
    } finally {
      tempDir.deleteSync(recursive: true);
    }
  });
}
