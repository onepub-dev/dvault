import 'package:dvault/src/dvault.dart';
import 'package:test/test.dart';

void main() {
  test('encrypt ...', () {
    runCommand(['lock', 'test/data/test_one.txt']);
  });
}
