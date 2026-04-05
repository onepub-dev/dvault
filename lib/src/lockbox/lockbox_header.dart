import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:dvault/src/util/byte_data_helper.dart';
import 'package:dvault/src/vfs/lock_box_reader.dart';
import 'package:dvault/src/vfs/lock_box_writer.dart';

import 'lockbox_format.dart';
import 'recipient.dart';

class LockBoxHeader {
  final int version;
  final int pageSize;
  final int tocOffset;
  final List<Recipient> recipients;

  // Calculated field
  late final int headerSize;

  LockBoxHeader.LockBoxHeader({
    required this.version,
    required this.pageSize,
    required this.tocOffset,
    required this.recipients,
  }) {
    headerSize = _calculateSize();
  }

  /// The space available for data in a page.
  int get pageContentSize => pageSize - LockBoxFormat.pageOverhead;

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
    buffer.setRange(offset, offset + 6, LockBoxFormat.magicBytes);
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

  /// Reads the header from a file.
  static Future<LockBoxHeader> read(LockBoxReader reader) async {
    // Read Header
    // Read minimum header size to extract the headerSize field
    final minHeaderBytes = await reader.readBytesAt(
      0,
      LockBoxFormat.minHeaderSize,
    );
    if (minHeaderBytes.length < LockBoxFormat.minHeaderSize) {
      throw FormatException('File too short');
    }

    // Extract the full header size using the LockboxHeader helper
    final fullHeaderSize = LockBoxHeader.extractHeaderSize(minHeaderBytes);

    // Read the remaining header bytes
    final remainingBytes = fullHeaderSize - LockBoxFormat.minHeaderSize;
    final remainingHeaderBytes = await reader.readBytesAt(
      LockBoxFormat.minHeaderSize,
      remainingBytes,
    );

    if (remainingHeaderBytes.length < remainingBytes) {
      throw FormatException(
        'Incomplete header: expected $remainingBytes more bytes, got ${remainingHeaderBytes.length}',
      );
    }

    // Combine minimum header + remaining bytes for full header
    final fullHeaderBytes = Uint8List(fullHeaderSize);
    fullHeaderBytes.setRange(0, LockBoxFormat.minHeaderSize, minHeaderBytes);
    fullHeaderBytes.setRange(
      LockBoxFormat.minHeaderSize,
      fullHeaderSize,
      remainingHeaderBytes,
    );

    // Now deserialize the complete header
    return LockBoxHeader.fromBytes(fullHeaderBytes);
  }

  Future<void> write(LockBoxWriter writer) async {
    await writer.writeBytesAt(0, toBytes());
  }

  /// Extracts the full header size from minimum header bytes.
  /// This allows reading the header in two stages:
  /// 1. Read minHeaderSize bytes
  /// 2. Extract the full size using this method
  /// 3. Read remaining bytes
  /// 4. Deserialize with fromBytes()
  static int extractHeaderSize(Uint8List minHeaderBytes) {
    if (minHeaderBytes.length < LockBoxFormat.minHeaderSize) {
      throw FormatException('Insufficient bytes to extract header size');
    }

    // Header Size is at offset 20 (Magic:6 + Version:2 + PageSize:4 + TOC:8)
    final data = ByteData.view(minHeaderBytes.buffer);
    return data.getUint32(20, Endian.little);
  }

  /// Parses the header from a byte list.
  static LockBoxHeader fromBytes(Uint8List bytes) {
    if (bytes.length < LockBoxFormat.minHeaderSize) {
      throw FormatException('Invalid header size: too small');
    }

    final data = ByteData.view(bytes.buffer);
    int offset = 0;

    // Magic Bytes
    final magic = bytes.sublist(offset, offset + 6);
    if (!const ListEquality<int>().equals(magic, LockBoxFormat.magicBytes)) {
      throw FormatException('Invalid magic bytes');
    }
    offset += 6;

    // Version
    final version = data.getUint16(offset, Endian.little);
    if (version != LockBoxFormat.version) {
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

    return LockBoxHeader.LockBoxHeader(
      version: version,
      pageSize: pageSize,
      tocOffset: tocOffset,
      recipients: recipients,
    );
  }
}
