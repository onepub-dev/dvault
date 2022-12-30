@Timeout(Duration(minutes: 5))
/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:async/async.dart';
import 'package:dcli/dcli.dart' hide equals;
import 'package:dvault/src/file_encryptor.dart';
import 'package:dvault/src/util/raf_helper.dart';
import 'package:test/test.dart';

void main() {
  test('file encryptor ...', () {
    final encryptor = FileEncryptor.noEncryption();

    const testFile = 'testfile.txt';
    // ignore: cascade_invocations
    testFile
      ..write('1Hello World')
      ..append('2Hello World');

    const pathToSecurityBox = 'testfile.sbox';

    
    await withRandomAccessFile(pathToSecurityBox, (rafSecurityBox) {
      /// encrypt the file
      encryptor.encrypt(testFile, rafSecurityBox);
    });

    // decrypt the file
    const resultFile = 'result.txt';
    if (exists(resultFile)) {
      delete(resultFile);
    }
    final resultSink = File(resultFile).openWrite();
    final reader =
        ChunkedReader(ChunkedStreamReader(File(pathToSecurityBox).openRead()));
    try {
      encryptor.decryptFiieReader(reader, resultSink);
    } finally {
      // ignore: discarded_futures
      waitForEx<void>(resultSink.close());
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
      File(testFile).writeAsStringSync(toStore);
      final encryptedFile = _lock(testFile, encryptor);
      // block size is 16 bits so should always be multiple of two
      // the mini security box has an 8 byte header to store
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
  const pathToSecurityBox = 'testfile.sbox';
  withOpenFile(pathToSecurityBox, (securityBox) {
    encryptor.encrypt(pathToPlainText, securityBox);
  });

  return pathToSecurityBox;
}

String _unlock(
  String pathToEncryptedFile,
  FileEncryptor encryptor,
) {
  const resultFile = 'result.txt';

  final writeTo = File(resultFile).openWrite();
  try {
    // ignore: discarded_futures
    waitForEx(encryptor.decrypt(pathToEncryptedFile, writeTo));
  } finally {
    // ignore: discarded_futures
    waitForEx<void>(writeTo.close());
  }

  return resultFile;
}
