import 'dart:io';
import 'dart:typed_data';

import 'package:dvault/src/lockbox/lockbox.dart';
import 'package:dvault/src/lockbox/lockbox_format.dart';
import 'package:dvault/src/lockbox/lockbox_header.dart';
import 'package:dvault/src/util/strong_key.dart';
import 'package:dvault/src/vfs/io_lockbox.dart';
import 'package:test/test.dart';

void main() {
  test('Header reading debug test', () async {
    final tempDir = Directory.systemTemp.createTempSync('header_test_');
    final vaultFile = File('${tempDir.path}/test.${LockBox.extension}');

    try {
      // Create a lockbox
      print('Creating lockbox...');
      final lockbox1 = await IOLockBox.open(
        file: vaultFile,
        strongKey: await StrongKey.fromString('test123'),
        create: true,
      );

      // Write some data
      await lockbox1.addFile(
        'test.txt',
        Uint8List.fromList('Hello World'.codeUnits),
      );
      await lockbox1.closeFile();

      print('Vault created, file size: ${await vaultFile.length()}');

      // Read the file manually to check header
      final raf = await vaultFile.open();
      await raf.setPosition(0);
      final minBytes = await raf.read(LockBoxFormat.minHeaderSize);
      print('Min header bytes length: ${minBytes.length}');

      final headerSize = LockBoxHeader.extractHeaderSize(minBytes);
      print('Extracted header size: $headerSize');

      await raf.setPosition(0);
      final fullBytes = await raf.read(headerSize);
      print('Full header bytes length: ${fullBytes.length}');

      final header = LockBoxHeader.fromBytes(fullBytes);
      print('Header parsed successfully!');
      print('  Version: ${header.version}');
      print('  Page size: ${header.pageSize}');
      print('  TOC offset: ${header.tocOffset}');
      print('  Recipients: ${header.recipients.length}');
      print('  Header size: ${header.headerSize}');

      await raf.close();

      // Now try to reopen the vault
      print('\nReopening vault...');
      final vault2 = await IOLockBox.open(
        file: vaultFile,
        strongKey: await StrongKey.fromString('test123'),
      );

      final data = await vault2.read('test.txt');
      print('Read data: ${String.fromCharCodes(data)}');

      await vault2.closeFile();

      expect(String.fromCharCodes(data), equals('Hello World'));
    } finally {
      tempDir.deleteSync(recursive: true);
    }
  });
}
