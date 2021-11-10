@Timeout(Duration(minutes: 5))
import 'package:dcli/dcli.dart' hide equals;

import 'package:dvault/src/file_encryptor.dart';
import 'package:dvault/src/vault.dart';
import 'package:test/test.dart';

void main() {
  test('vault ...', () {
    withTempDir((dir) {
      final vaultPath = join(dir, 'test.vault');
      var vault = VaultFile(vaultPath);

      withTempFile(
        (pathToFileToEncrypt) {
          _createFile(pathToFileToEncrypt, 2);
          vault.addFile(
            pathToFileToEncrypt,
            relativeTo: dir,
          );
          vault.saveTo();
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

          vault.iv;

          withTempDir((extractToDir) {
            vault.extractFiles(extractToDir);

            final pathToExtractedFile =
                join(extractToDir, vault.toc.entries.first.relativePathToFile);

            expect(
              vault.toc.entries.first.originalLength,
              equals(stat(pathToExtractedFile).size),
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

int _encryptedFileSize(String path) {
  final fileSize = stat(path).size;
  final blockSize = FileEncryptor.noEncryption().blockSize;

  return fileSize + (blockSize - fileSize % blockSize);
}

void _createFile(String pathToFile, int base) {
  withOpenFile(pathToFile, (file) {
    file.append('$base' * 100);
    file.append('$base' * 100);
    file.append('$base' * 100);
  });
}