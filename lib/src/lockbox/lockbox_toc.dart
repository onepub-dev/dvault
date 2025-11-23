import 'dart:convert';
import 'dart:typed_data';

import 'package:dvault/src/lockbox/file_entry.dart';
import 'package:dvault/src/util/byte_data_helper.dart';

class LockboxTOC {
  final Map<String, FileEntry> files = {};

  LockboxTOC();

  /// Serializes the TOC to a byte list.
  Uint8List toBytes() {
    final buffer = BytesBuilder();

    // Files
    // Count (4)
    final countBytes = Uint8List(4);
    ByteData.view(countBytes.buffer).setUint32(0, files.length, Endian.little);
    buffer.add(countBytes);

    for (final entry in files.values) {
      final pathBytes = utf8.encode(entry.path);

      // Path Length (2)
      final lenBytes = Uint8List(2);
      ByteData.view(
        lenBytes.buffer,
      ).setUint16(0, pathBytes.length, Endian.little);
      buffer.add(lenBytes);

      // Path
      buffer.add(pathBytes);

      // Offset (8), Length (8), Created (8), Modified (8)
      final metaBytes = Uint8List(32);
      final metaData = ByteData.view(metaBytes.buffer);
      ByteDataHelper.setUint64(metaData, 0, entry.offset, Endian.little);
      ByteDataHelper.setUint64(metaData, 8, entry.length, Endian.little);
      ByteDataHelper.setUint64(metaData, 16, entry.created, Endian.little);
      ByteDataHelper.setUint64(metaData, 24, entry.modified, Endian.little);
      buffer.add(metaBytes);
    }

    return buffer.toBytes();
  }

  /// Parses the TOC from a byte list.
  static LockboxTOC fromBytes(Uint8List bytes) {
    final toc = LockboxTOC();
    final data = ByteData.view(bytes.buffer);
    int offset = 0;

    // Files
    if (offset + 4 > bytes.length)
      throw FormatException('Truncated TOC (File Count)');
    final fileCount = data.getUint32(offset, Endian.little);
    offset += 4;

    for (int i = 0; i < fileCount; i++) {
      // Path Length
      if (offset + 2 > bytes.length)
        throw FormatException('Truncated TOC (Path Len)');
      final pathLen = data.getUint16(offset, Endian.little);
      offset += 2;

      // Path
      if (offset + pathLen > bytes.length)
        throw FormatException('Truncated TOC (Path)');
      final path = utf8.decode(bytes.sublist(offset, offset + pathLen));
      offset += pathLen;

      // Metadata
      if (offset + 32 > bytes.length)
        throw FormatException('Truncated TOC (Metadata)');
      final fileOffset = ByteDataHelper.getUint64(data, offset, Endian.little);
      final fileLength = ByteDataHelper.getUint64(
        data,
        offset + 8,
        Endian.little,
      );
      final created = ByteDataHelper.getUint64(
        data,
        offset + 16,
        Endian.little,
      );
      final modified = ByteDataHelper.getUint64(
        data,
        offset + 24,
        Endian.little,
      );
      offset += 32;

      toc.files[path] = FileEntry(
        path: path,
        offset: fileOffset,
        length: fileLength,
        created: created,
        modified: modified,
      );
    }

    return toc;
  }
}
