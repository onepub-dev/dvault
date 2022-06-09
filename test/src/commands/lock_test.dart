/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dvault/src/dvault.dart';
import 'package:test/test.dart';

void main() {
  test('encrypt ...', () {
    runCommand(['lock', 'test/data/test_one.txt']);
  });
}
