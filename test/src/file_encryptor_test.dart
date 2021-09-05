@Timeout(Duration(minutes: 5))
import 'dart:io';

import 'package:async/async.dart';
import 'package:dvault/src/file_encryptor.dart';
import 'package:test/test.dart';
import 'package:dcli/dcli.dart' hide equals;

void main() {
  test('file encryptor ...', () async {
    var encryptor = FileEncryptor.noEncryption();

    final testFile = 'testfile.txt';
    testFile.write('1Hello World');
    testFile.append('2Hello World');

    final vault = 'testfile.vault';
    var writeTo = File(vault).openWrite();

    /// encrypt the file
    try {
      await encryptor.encrypt(testFile, writeTo);
    } finally {
      await writeTo.close();
    }

    // decrypt the file
    final resultFile = 'result.txt';
    if (exists(resultFile)) delete(resultFile);
    var resultSink = File(resultFile).openWrite();
    final reader = ChunkedStreamReader(File(vault).openRead());
    try {
      await encryptor.decryptStream(reader, resultSink);
    } finally {
      await resultSink.close();
      await reader.cancel();
    }

    expect(stat(resultFile).size, equals(stat(testFile).size));
    expect(
        read(resultFile).toParagraph(), equals(read(testFile).toParagraph()));
  });

  test('Test Padding', () async {
    var encryptor = FileEncryptor.noEncryption();

    // 32 chars
    var text = 'abcdefghijklmnopqrstuvwxyz01234567';

    final testFile = 'testfile.txt';
    for (var size = 2; size <= 32; size++) {
      var toStore = text.substring(0, size);
      var file = File(testFile);
      file.writeAsStringSync(toStore);
      var encryptedFile = await _lock(testFile, encryptor);
      // block size is 16 bits so should always be multiple of two
      // the mini vault has an 8 byte header to store
      /// the actual size of the file.
      var expectedContent = stat(encryptedFile).size - 8;
      expect((expectedContent % 2) == 0, isTrue);

      var resultsFile = await _unlock(encryptedFile, encryptor);
      expect(stat(resultsFile).size == size, isTrue);
      expect(read(resultsFile).toParagraph(), equals(toStore));
    }
  });
}

Future<String> _lock(String pathToPlainText, FileEncryptor encryptor) async {
  final vault = 'testfile.vault';
  var writeTo = File(vault).openWrite();

  try {
    await encryptor.encrypt(pathToPlainText, writeTo);
  } finally {
    await writeTo.close();
  }

  return vault;
}

Future<String> _unlock(
    String pathToEncryptedFile, FileEncryptor encryptor) async {
  final resultFile = 'result.txt';

  var writeTo = File(resultFile).openWrite();
  try {
    await encryptor.decrypt(pathToEncryptedFile, writeTo);
  } finally {
    await writeTo.close();
  }

  return resultFile;
}
