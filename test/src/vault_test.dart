@Timeout(Duration(minutes: 5))
/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dcli_core/dcli_core.dart';
import 'package:dvault/src/file_encryptor.dart';
import 'package:dvault/src/security_box/security_box.dart';
import 'package:path/path.dart' hide equals;
import 'package:test/test.dart';

void main() {
  test('security box ...', () async {
    await withTempDirAsync((dir) async {
      final pathToSecurityBox = join(dir, 'test.sbox');
      var securityBox = SecurityBox(pathToSecurityBox);

      await withTempFileAsync(
        (pathToFileToEncrypt) async {
          await _createFile(pathToFileToEncrypt, 2);
          securityBox.addFileToIndex(
            pathToFileToEncrypt,
            relativeTo: dir,
          );
          // await .create();
          // expect(securityBox.toc.entries.length, equals(1));
          expect(securityBox.toc.content.length, equals(1));
          expect(
            (await securityBox.toc.content.first).originalPathToFile,
            equals(pathToFileToEncrypt),
          );
          expect(
            (await securityBox.toc.content.first).length,
            equals(
              _encryptedFileSize(
                  (await securityBox.toc.content.first).originalPathToFile),
            ),
          );

          securityBox = await SecurityBox.load(pathToSecurityBox);
          // check the TOCEntry
          expect(securityBox.toc.content.length, equals(1));
          expect(
            (await securityBox.toc.content.first).relativePathToFile,
            equals(relative(pathToFileToEncrypt, from: dir)),
          );
          expect(
            (await securityBox.toc.content.first).length,
            equals(
              _encryptedFileSize(
                join(dir,
                    (await securityBox.toc.content.first).relativePathToFile),
              ),
            ),
          );

          await withTempDirAsync((extractToDir) async {
            await securityBox.loadFromDisk(extractToDir);

            final pathToExtractedFile = join(extractToDir,
                (await securityBox.toc.content.first).relativePathToFile);

            expect(
              (await securityBox.toc.content.first).originalLength,
              equals((await stat(pathToExtractedFile)).size),
            );
            final originalDigest = calculateHash(pathToFileToEncrypt);
            final newDigest = calculateHash(pathToExtractedFile);

            expect(originalDigest, equals(newDigest));
          });
        },
        pathToTempDir: dir,
      );
    });
  });
}

Future<int> _encryptedFileSize(String path) async {
  final fileSize = (await stat(path)).size;
  final blockSize = FileEncryptor.noEncryption().blockSize;

  return fileSize + (blockSize - fileSize % blockSize);
}

Future<void> _createFile(String pathToFile, int base) async {
  await withOpenFile(pathToFile, (file) async {
    await file.writeString('$base' * 100);
    await file.writeString('$base' * 100);
    await file.writeString('$base' * 100);
  });
}
