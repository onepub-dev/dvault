import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:dvault/src/util/byte_data_helper.dart';

import 'lockbox_format.dart';
import 'recipient.dart';

class LockboxHeader {
  final int version;
  final int pageSize;
  final int tocOffset;
  final List<Recipient> recipients;

  // Calculated field
  late final int headerSize;

  LockboxHeader({
    required this.version,
    required this.pageSize,
    required this.tocOffset,
    required this.recipients,
  }) {
    headerSize = _calculateSize();
  }

  int _calculateSize() {
    // Magic(6) + Version(2) + PageSize(4) + TOC Offset(8) + HeaderSize(4) + RecipientCount(2)
    int size = 26;
    for (final recipient in recipients) {
      size += recipient.toBytes().length;
    }
    return size;
  }

  /// Serializes the header to a byte list.
  Uint8List toBytes() {
    final buffer = Uint8List(headerSize);
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

    // Header Size (4)
    data.setUint32(offset, headerSize, Endian.little);
    offset += 4;

    // Recipient Count (2)
    data.setUint16(offset, recipients.length, Endian.little);
    offset += 2;

    // Recipients
    for (final recipient in recipients) {
      final recipientBytes = recipient.toBytes();
      buffer.setRange(offset, offset + recipientBytes.length, recipientBytes);
      offset += recipientBytes.length;
    }

    return buffer;
  }

  /// Parses the header from a byte list.
  static LockboxHeader fromBytes(Uint8List bytes) {
    if (bytes.length < LockboxFormat.minHeaderSize) {
      throw FormatException('Invalid header size: too small');
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

    // Header Size
    final headerSize = data.getUint32(offset, Endian.little);
    offset += 4;

    if (bytes.length < headerSize) {
      throw FormatException('Incomplete header data');
    }

    // Recipient Count
    final recipientCount = data.getUint16(offset, Endian.little);
    offset += 2;

    // Recipients
    final recipients = <Recipient>[];
    for (int i = 0; i < recipientCount; i++) {
      final (recipient, bytesRead) = Recipient.fromBytes(bytes, offset);
      recipients.add(recipient);
      offset += bytesRead;
    }

    return LockboxHeader(
      version: version,
      pageSize: pageSize,
      tocOffset: tocOffset,
      recipients: recipients,
    );
  }
}
