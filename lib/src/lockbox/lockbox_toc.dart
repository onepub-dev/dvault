import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dvault/src/lockbox/file_entry.dart';
import 'package:dvault/src/lockbox/lockbox_format.dart';
import 'package:dvault/src/lockbox/lockbox_page.dart';
import 'package:dvault/src/util/byte_data_helper.dart';
import 'package:dvault/src/vfs/lock_box_writer.dart';

class LockBoxTOC {
  final Map<String, FileEntry> _files = {};

  LockBoxTOC();

  /// Serializes the TOC to a byte list.
  Uint8List toBytes() {
    final buffer = BytesBuilder();

    // Files
    // Count (4)
    final countBytes = Uint8List(4);
    ByteData.view(countBytes.buffer).setUint32(0, _files.length, Endian.little);
    buffer.add(countBytes);

    for (final entry in _files.values) {
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

  Future<void> write(
    LockBoxWriter writer,
    int pageOffset,
    int pageSize,
    SecretKey sessionKey,
  ) async {
    final bytes = toBytes();

    final payloadSize = pageSize - LockBoxFormat.pageOverhead;
    var offset = 0;
    var pageIndex = 0;

    while (offset < bytes.length) {
      final remaining = bytes.length - offset;
      final toWrite = remaining > payloadSize ? payloadSize : remaining;

      final pageData = Uint8List(payloadSize);
      pageData.setRange(0, toWrite, bytes.sublist(offset, offset + toWrite));

      final encryptedPage = await LockBoxPage.encrypt(
        data: pageData,
        key: sessionKey,
        pageSize: pageSize,
      );

      final physicalOffset = pageOffset + (pageIndex * pageSize);
      await writer.writeBytesAt(physicalOffset, encryptedPage);

      offset += toWrite;
      pageIndex++;
    }
  }

  /// True if [path] exists in the TOC.
  bool exists(String path) => _files.containsKey(path);

  int get count => _files.length;

  FileEntry? stat(String path) => _files[path];

  bool get isNotEmpty => _files.isNotEmpty;

  bool get isEmpty => _files.isEmpty;

  FileEntry get lastFile => _files.values.reduce(
    (a, b) => a.offset + a.length > b.offset + b.length ? a : b,
  );

  /// Parses the TOC from a byte list.
  static LockBoxTOC fromBytes(Uint8List bytes) {
    final toc = LockBoxTOC();
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

      toc._files[path] = FileEntry(
        path: path,
        offset: fileOffset,
        length: fileLength,
        created: created,
        modified: modified,
      );
    }

    return toc;
  }

  void append(String path, FileEntry fileEntry) {
    _files[path] = fileEntry;
  }

  bool isDirectory(String path) {
    if (path == '/' || path == '') return true;
    final prefix = path.endsWith('/') ? path : '$path/';
    for (final key in _files.keys) {
      if (key.startsWith(prefix)) return true;
    }
    return false;
  }

  List<String> list(String path, {bool recursive = false}) {
    final entries = <String>{};
    final prefix =
        (path == '/' || path == '')
            ? ''
            : (path.endsWith('/') ? path : '$path/');

    for (final key in _files.keys) {
      if (key.startsWith(prefix)) {
        if (recursive) {
          entries.add(key);
        } else {
          final relative = key.substring(prefix.length);
          final parts = relative.split('/');
          if (parts.isNotEmpty) {
            entries.add(prefix + parts[0]);
          }
        }
      }
    }
    return entries.toList();
  }

  FileEntry? remove(String path) {
    return _files.remove(path);
  }
}
