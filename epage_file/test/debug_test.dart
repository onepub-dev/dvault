import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:epage_file/epage_file.dart';
import 'package:test/test.dart';

void main() async {
  test("Write to EPageFile and debug lengths", () async {
    final tempDir = Directory.systemTemp.createTempSync('epage_debug_');
    final testFilePath = '${tempDir.path}/test.epage';

    try {
      print('Creating file...');
      final key = SecretKey(List.filled(32, 42));
      final store = await FileBackingStore.open(testFilePath);
      final file = await EPageFile.open(store, key: key);

      print('Writing data...');
      final writeData = Uint8List.fromList('Hello, World!'.codeUnits);
      await file.writeAt(0, writeData);

      print('Flushing...');
      await file.flush();

      print('File length after flush: ${await File(testFilePath).length()}');

      print('Closing...');
      await file.close();

      print('File length after close: ${await File(testFilePath).length()}');

      final store2 = await FileBackingStore.open(testFilePath);
      final file2 = await EPageFile.open(store2, key: key);

      final readData = await file2.readAt(0, writeData.length);
      expect(readData, writeData);

      await file2.close();
    } finally {
      tempDir.deleteSync(recursive: true);
    }
  });
}
