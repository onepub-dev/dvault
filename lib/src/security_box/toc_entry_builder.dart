/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dcli/dcli.dart';
import 'package:dvault/src/security_box/line.dart';
import 'package:path/path.dart';

import '../util/exceptions.dart';
import '../util/raf_helper.dart';

class TOCEntryBuilder implements Line {
  static const relativePathKey = 'relativePath';
  static const offsetKey = 'offset';
  static const lengthKey = 'length';
  static const originalLengthKey = 'originalLength';

  TOCEntryBuilder({required String pathToFile, required this.relativeTo})
      : originalLength = stat(pathToFile).size,
        relativePathToFile = relative(pathToFile, from: relativeTo);

  final String? relativeTo;

  // The relative path of the file in the ssecurity box
  late final String relativePathToFile;

  /// The offset (in bytes) from the start of the vault
  /// to where the data for this file is located.
  /// Only set if the data has been written to the vault
  late final int? offset;

  /// The length (in bytes) of the file after it has
  /// been encrypted.
  /// Only set if the data has been written
  late final int? length;

  /// The length (in bytes) of the file before it
  /// was encrypted.
  late final int originalLength;

  TOCEntryBuilder.fromLine(String line) : relativeTo = null {
    final parts = line.split(',');
    if (parts.length != 4) {
      throw SecurityBoxReadException(
        'Expected 4 key/value pairs in TOC entry. Found $line',
      );
    }

    /// offset
    offset = parseNo(parts[0], offsetKey);
    length = parseNo(parts[1], lengthKey);
    originalLength = parseNo(parts[2], originalLengthKey);
    relativePathToFile = parseValue(parts[3], relativePathKey);
  }

  @override
  String get asString => '$offsetKey:${offset}, $lengthKey:$length, '
      '$originalLengthKey:$originalLength, '
      '$relativePathKey:$relativePathToFile';
}
