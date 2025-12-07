import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:epage_file/epage_file.dart';
import 'package:epage_file/src/core/header.dart';
import 'package:test/test.dart';

void main() {
  test('raw file layout remains encrypted/structured', () async {
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
      expect(rawBytes.length, greaterThan(EPageFileHeader.headerSize));

      // Header magic/version present, rest should be non-plaintext
      final magic = String.fromCharCodes(
        rawBytes.sublist(0, 8),
      ).trim();
      expect(magic, contains('LOCKBOX'));

      final payloadSlice = rawBytes.sublist(
        EPageFileHeader.headerSize,
        EPageFileHeader.headerSize + 64,
      );
      expect(payloadSlice, isNot(equals(data.take(64).toList())));
    } finally {
      tempDir.deleteSync(recursive: true);
    }
  });
}
