/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */


import 'package:dcli/dcli.dart';

import 'util/exceptions.dart';
import 'util/raf_helper.dart';

/// A TOCEntry represents a file stored in the vault
/// The contents of the file are encrypted using the
/// Public Key of user that create the vault.
/// The file an only be decrypted using the Private Key
/// which is contained in the vault.
class TOCEntry {
  TOCEntry({required String pathToFile, required this.relativeTo})
      : originalLength = stat(pathToFile).size,
        relativePathToFile = relative(pathToFile, from: relativeTo);

  TOCEntry.fromParts({
    required this.offset,
    required this.length,
    required this.originalLength,
    required this.relativePathToFile,
  }) : relativeTo = null;

  /// The path on the source system that [relativePathToFile] is
  /// relative to. This value is not stored in the vault
  /// as its not required when extracting files and
  /// as such will be null when the [TOCEntry] is
  /// loaded from a vault.
  /// It should also NEVER be stored in the vault
  /// as it would constitute a leakage of the creator
  /// of the vault's personal information.
  final String? relativeTo;

  // The relative path of the file in the Vault
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

  String get asLine =>
      '$offsetKey:$offset, $lengthKey:$length, $originalLengthKey:$originalLength, $relativePathKey:$relativePathToFile';

  TOCEntry.fromLine(String line) : relativeTo = null {
    final parts = line.split(',');
    if (parts.length != 4) {
      throw VaultReadException(
        'Expected 4 key/value pairs in TOC entry. Found $line',
      );
    }

    /// offset
    offset = parseNo(parts[0], offsetKey);
    length = parseNo(parts[1], lengthKey);
    originalLength = parseNo(parts[2], originalLengthKey);
    relativePathToFile = parseValue(parts[3], relativePathKey);
  }

  /// This method is only valid when creating the vault.
  /// If you are loading an existing vault call this file will
  ///
  String get originalPathToFile {
    if (relativeTo == null) {
      throw StateError('This method is only available when creating a vault');
    }
    return join(relativeTo!, relativePathToFile);
  }
}
