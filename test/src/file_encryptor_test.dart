@Timeout(Duration(minutes: 5))
import 'dart:cli';
import 'dart:io';

import 'package:async/async.dart';
import 'package:dcli/dcli.dart' hide equals;
import 'package:dvault/src/file_encryptor.dart';
import 'package:test/test.dart';

void main() {
  test('file encryptor ...', () {
    final encryptor = FileEncryptor.noEncryption();

    const testFile = 'testfile.txt';
    testFile.write('1Hello World');
    testFile.append('2Hello World');

    const pathToVvault = 'testfile.vault';
    withOpenFile(pathToVvault, (vault) {
      /// encrypt the file
      encryptor.encrypt(testFile, vault);
    });

    // decrypt the file
    const resultFile = 'result.txt';
    if (exists(resultFile)) delete(resultFile);
    final resultSink = File(resultFile).openWrite();
    final reader =
        ChunkedReader(ChunkedStreamReader(File(pathToVvault).openRead()));
    try {
      encryptor.decryptReader(reader, resultSink);
    } finally {
      waitFor(resultSink.close());
      reader.cancel();
    }

    expect(stat(resultFile).size, equals(stat(testFile).size));
    expect(
      read(resultFile).toParagraph(),
      equals(read(testFile).toParagraph()),
    );
  });

  test('Test Padding', () {
    final encryptor = FileEncryptor.noEncryption();

    // 32 chars
    const text = 'abcdefghijklmnopqrstuvwxyz01234567';

    const testFile = 'testfile.txt';
    for (var size = 2; size <= 32; size++) {
      final toStore = text.substring(0, size);
      final file = File(testFile);
      file.writeAsStringSync(toStore);
      final encryptedFile = _lock(testFile, encryptor);
      // block size is 16 bits so should always be multiple of two
      // the mini vault has an 8 byte header to store
      /// the actual size of the file.
      final expectedContent = stat(encryptedFile).size - 8;
      expect((expectedContent % 2) == 0, isTrue);

      final resultsFile = _unlock(encryptedFile, encryptor);
      expect(stat(resultsFile).size == size, isTrue);
      expect(read(resultsFile).toParagraph(), equals(toStore));
    }
  });
}

String _lock(String pathToPlainText, FileEncryptor encryptor) {
  const pathToVault = 'testfile.vault';
  withOpenFile(pathToVault, (vault) {
    encryptor.encrypt(pathToPlainText, vault);
  });

  return pathToVault;
}

String _unlock(
  String pathToEncryptedFile,
  FileEncryptor encryptor,
) {
  const resultFile = 'result.txt';

  final writeTo = File(resultFile).openWrite();
  try {
    encryptor.decrypt(pathToEncryptedFile, writeTo);
  } finally {
    writeTo.close();
  }

  return resultFile;
}
