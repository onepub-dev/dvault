import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:dvault/src/util/byte_data_helper.dart';

import 'lockbox_format.dart';

class LockboxHeader {
  final int version;
  final int pageSize;
  final int tocOffset;
  final Uint8List salt;
  final Uint8List kdfParams;

  LockboxHeader({
    required this.version,
    required this.pageSize,
    required this.tocOffset,
    required this.salt,
    required this.kdfParams,
  });

  /// Serializes the header to a byte list.
  Uint8List toBytes() {
    final buffer = Uint8List(LockboxFormat.headerSize);
    final data = ByteData.view(buffer.buffer);
    int offset = 0;

    // Magic Bytes (6)
    buffer.setRange(offset, offset + 6, LockboxFormat.magicBytes);
    offset += 6;

    // Version (2)
    data.setUint16(offset, version, Endian.little);
    offset += 2;

    // Page Size (4)
    data.setUint32(offset, pageSize, Endian.little);
    offset += 4;

    // TOC Offset (8)
    ByteDataHelper.setUint64(data, offset, tocOffset, Endian.little);
    offset += 8;

    // Salt (16)
    if (salt.length != 16) throw ArgumentError('Salt must be 16 bytes');
    buffer.setRange(offset, offset + 16, salt);
    offset += 16;

    // KDF Params (16)
    if (kdfParams.length != 16)
      throw ArgumentError('KDF Params must be 16 bytes');
    buffer.setRange(offset, offset + 16, kdfParams);
    offset += 16;

    // Reserved (12) - Zeroed by default

    return buffer;
  }

  /// Parses the header from a byte list.
  static LockboxHeader fromBytes(Uint8List bytes) {
    if (bytes.length != LockboxFormat.headerSize) {
      throw FormatException('Invalid header size');
    }

    final data = ByteData.view(bytes.buffer);
    int offset = 0;

    // Magic Bytes
    final magic = bytes.sublist(offset, offset + 6);
    if (!const ListEquality<int>().equals(magic, LockboxFormat.magicBytes)) {
      throw FormatException('Invalid magic bytes');
    }
    offset += 6;

    // Version
    final version = data.getUint16(offset, Endian.little);
    if (version != LockboxFormat.version) {
      throw FormatException('Unsupported version: $version');
    }
    offset += 2;

    // Page Size
    final pageSize = data.getUint32(offset, Endian.little);
    offset += 4;

    // TOC Offset
    final tocOffset = ByteDataHelper.getUint64(data, offset, Endian.little);
    offset += 8;

    // Salt
    final salt = bytes.sublist(offset, offset + 16);
    offset += 16;

    // KDF Params
    final kdfParams = bytes.sublist(offset, offset + 16);
    offset += 16;

    return LockboxHeader(
      version: version,
      pageSize: pageSize,
      tocOffset: tocOffset,
      salt: salt,
      kdfParams: kdfParams,
    );
  }
}
