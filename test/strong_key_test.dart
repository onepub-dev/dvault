import 'dart:typed_data';

import 'package:dvault/src/util/strong_key.dart';
import 'package:test/test.dart';

void main() {
  test('asSecretKey returns equivalent bytes', () async {
    final source = Uint8List.fromList('test-passphrase'.codeUnits);
    final strongKey = StrongKey.fromPassPhrase(source);

    final salt = StrongKey.generateSalt();
    final secretKey = await strongKey.deriveSecretKey(
      salt: salt,
      iterations: 2,
      desiredKeyLength: 32,
    );
    final extracted = await secretKey.extractBytes();

    expect(extracted.length, 32);
    expect(extracted, isNot(equals(source)));
  });
}
