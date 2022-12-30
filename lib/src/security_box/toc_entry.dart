/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dcli/dcli.dart';

import '../util/exceptions.dart';
import '../util/raf_helper.dart';

/// A TOCEntry represents a file stored in the security box
/// The contents of the file are encrypted using the
/// Public Key of the user that created the security box.
/// The file can only be decrypted using the Private Key
/// which is contained in the security box encrypted using the user's
/// passphrase
class TOCEntry {
  TOCEntry({required String pathToFile, required this.relativeTo})
      : originalLength = stat(pathToFile).size,
        relativePathToFile = relative(pathToFile, from: relativeTo);

  TOCEntry.fromLine(String line) : relativeTo = null {
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

  TOCEntry.fromParts({
    required this.offset,
    required this.length,
    required this.originalLength,
    required this.relativePathToFile,
  }) : relativeTo = null;

  /// The path on the source system that [relativePathToFile] is
  /// relative to. This value is not stored in the security box
  /// as its not required when extracting files and
  /// as such will be null when the [TOCEntry] is
  /// loaded from a security box.
  /// It should also NEVER be stored in the security box
  /// as it would constitute a leakage of the creator
  /// of the security box's personal information.
  final String? relativeTo;

  // The relative path of the file in the ssecurity box
  late final String relativePathToFile;

  /// The offset (in bytes) from the start of the vault
  /// to where the data for this file is located.
  late final int offset;

  /// The length (in bytes) of the file after it has
  /// been encrypted.
  late final int length;

  /// The length (in bytes) of the file before it
  /// was encrypted.
  late final int originalLength;

  static const relativePathKey = 'relativePath';
  static const offsetKey = 'offset';
  static const lengthKey = 'length';
  static const originalLengthKey = 'originalLength';

  String get asLine => '$offsetKey:$offset, $lengthKey:$length, '
      '$originalLengthKey:$originalLength, '
      '$relativePathKey:$relativePathToFile';

  /// This method is only valid when creating the Security Box.
  /// If you are loading an existing security box call this method will
  /// throw a [StateError].
  String get originalPathToFile {
    if (relativeTo == null) {
      throw StateError(
          'This method is only available when creating a security box');
    }
    return join(relativeTo!, relativePathToFile);
  }
}
