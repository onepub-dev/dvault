import 'package:dcli/dcli.dart';
import 'package:dvault/src/lockbox/lockbox.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() {
  group('CLI Integration Tests', () {
    late String tempDir;
    late String vaultPath;
    const password = 'password123';

    setUp(() {
      tempDir = createTempDir();
      vaultPath = p.join(tempDir, 'test.${LockBox.extension}');
    });

    tearDown(() {
      deleteDir(tempDir);
    });

    test('init command creates vault', () {
      final result = 'dart bin/dvault.dart init $vaultPath --page-size 1024'
          .start(progress: Progress.capture(), nothrow: true);
      // We need to feed password. DCLI `start` doesn't easily support interactive input for tests.
      // We might need to mock `ask` or use `Process.start`.
    });
  });
}
