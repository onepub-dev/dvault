import 'package:dcli/dcli.dart';

import 'util/exceptions.dart';
import 'util/raf_helper.dart';

/// A TOCEntry represents a file stored in the vault
/// The contents of the file are encrypted using the
/// Public Key of user that create the vault.
/// The file an only be decrypted using the Private Key
/// which is contained in the vault.
class TOCEntry {
  TOCEntry(this.path) : originalLength = stat(path).size;

  TOCEntry.fromParts(
      {required this.offset,
      required this.length,
      required this.originalLength,
      required this.path});

  // The path of the file in the Vault
  String path;

  /// The offset (in bytes) from the start of the vault
  /// to where the data for this file is located.
  late int offset;

  /// The length (in bytes) of this entry after it has
  /// been encrypted.
  late int length;

  int originalLength;

  String get asLine =>
      'offset:$offset, length: $length, originalLength: $originalLength, path: $path';

  static TOCEntry fromLine(String line) {
    var parts = line.split(',');
    if (parts.length != 4) {
      throw VaultReadException(
          'Expected 4 key/value pairs in TOC entry. Found $line');
    }

    /// offset
    var offset = parseNo(parts[0], 'offset');
    var length = parseNo(parts[1], 'length');
    var originalLength = parseNo(parts[2], 'originalLength');
    var path = parseValue(parts[3], 'path');

    return TOCEntry.fromParts(
        offset: offset,
        length: length,
        originalLength: originalLength,
        path: path);
  }
}
