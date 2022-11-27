@Timeout(Duration(minutes: 5))
/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dcli_core/dcli_core.dart';
import 'package:dvault/src/file_encryptor.dart';
import 'package:dvault/src/vault.dart';
import 'package:path/path.dart' hide equals;
import 'package:test/test.dart';

void main() {
  test('vault ...', () async {
    await withTempDir((dir) async {
      final vaultPath = join(dir, 'test.vault');
      var vault = VaultFile(vaultPath);

      await withTempFile(
        (pathToFileToEncrypt) async {
          await _createFile(pathToFileToEncrypt, 2);
          vault
            ..addFile(
              pathToFileToEncrypt,
              relativeTo: dir,
            )
            ..saveTo();
          expect(vault.toc.entries.length, equals(1));
          expect(
            vault.toc.entries.first.originalPathToFile,
            equals(pathToFileToEncrypt),
          );
          expect(
            vault.toc.entries.first.length,
            equals(
              _encryptedFileSize(vault.toc.entries.first.originalPathToFile),
            ),
          );

          vault = VaultFile.load(vaultPath);
          // check the TOCEntry
          expect(vault.toc.entries.length, equals(1));
          expect(
            vault.toc.entries.first.relativePathToFile,
            equals(relative(pathToFileToEncrypt, from: dir)),
          );
          expect(
            vault.toc.entries.first.length,
            equals(
              _encryptedFileSize(
                join(dir, vault.toc.entries.first.relativePathToFile),
              ),
            ),
          );

          await withTempDir((extractToDir) async {
            vault.extractFiles(extractToDir);

            final pathToExtractedFile =
                join(extractToDir, vault.toc.entries.first.relativePathToFile);

            expect(
              vault.toc.entries.first.originalLength,
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
