@Timeout(Duration(minutes: 5))
import 'package:dvault/src/file_encryptor.dart';
import 'package:dvault/src/vault.dart';
import 'package:test/test.dart';
import 'package:dcli/dcli.dart' hide equals;

void main() {
  test('vault ...', () async {
    var vault = VaultFile();

    withTempDir((dir) {
      var vaultPath = join(dir, 'test.vault');
      withTempFile((path) {
        _createFile(path, 1);
        vault.addFile(path);
        vault.saveTo(vaultPath);
        expect(vault.toc.entries.length, equals(1));
        expect(vault.toc.entries.first.path, equals(path));
        expect(vault.toc.entries.first.length,
            equals(_encryptedFileSize(vault.toc.entries.first.path)));

        vault = VaultFile.load(path);
        expect(vault.toc.entries.length, equals(1));
        expect(vault.toc.entries.first.path, equals(path));
        expect(vault.toc.entries.first.length,
            equals(_encryptedFileSize(vault.toc.entries.first.path)));
      });
    });
  });
}

int _encryptedFileSize(String path) {
  var fileSize = stat(path).size;
  var blockSize = FileEncryptor.noEncryption().blockSize;

  return fileSize + (blockSize - fileSize % blockSize);
}

void _createFile(String pathToFile, int base) {
  pathToFile.append('$base' * 100);
  pathToFile.append('$base' * 100);
  pathToFile.append('$base' * 100);
}
