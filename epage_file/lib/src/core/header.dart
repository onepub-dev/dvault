import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Represents the header of an EPageFile.
///
/// The header is stored at the beginning of the backing store (Page 0).
/// It contains metadata about the file, but only the magic string and version
/// remain in clear text. All other metadata is encrypted and Base64-encoded so
/// the header stays printable (no Ctrl-Z or other control bytes) when viewed
/// with tools like `cat`.
///
/// Structure (2048 bytes total):
/// - Magic String (8 bytes, ASCII, padded with spaces)
/// - Version (4 bytes, little endian)
/// - Base64 Length (4 bytes, little endian)
/// - Base64(nonce + ciphertext + mac) for the metadata block (ASCII)
/// - Remaining bytes are filled with a human-readable message
class EPageFileHeader {
  static const int headerSize = 2048;
  static const String magicString = 'LOCKBOX'; // Padded to 8 bytes
  static const int currentVersion = 1;
  static const int metadataPlaintextLength = 32; // bytes before encryption

  final int version;
  final int pageSize;
  int logicalLength;
  int pageCount;

  EPageFileHeader({
    required this.version,
    required this.pageSize,
    required this.logicalLength,
    required this.pageCount,
  });

  /// Creates a new default header.
  factory EPageFileHeader.create({required int pageSize}) {
    return EPageFileHeader(
      version: currentVersion,
      pageSize: pageSize,
      logicalLength: 0,
      pageCount: 0,
    );
  }

  /// Serializes the header to bytes using [key] to encrypt metadata.
  Future<Uint8List> toBytes(SecretKey key) async {
    final buffer = Uint8List(headerSize);
    // Pre-fill with a friendly message to keep output printable.
    final message = utf8.encode(
      'This is a dvault lockbox (epage) file. Do not edit. ',
    );
    for (var i = 0; i < buffer.length; i++) {
      buffer[i] = message[i % message.length];
    }

    final data = ByteData.view(buffer.buffer);
    var offset = 0;

    // Magic (padded to 8 bytes)
    final magicBytes = ascii.encode(magicString.padRight(8).substring(0, 8));
    buffer.setRange(offset, offset + magicBytes.length, magicBytes);
    offset += 8;

    // Version
    data.setUint32(offset, version, Endian.little);
    offset += 4;

    // Encrypt metadata
    final secretBox = await _encryptMetadata(key);
    final payload =
        Uint8List(
            secretBox.nonce.length +
                secretBox.cipherText.length +
                secretBox.mac.bytes.length,
          )
          ..setRange(0, secretBox.nonce.length, secretBox.nonce)
          ..setRange(
            secretBox.nonce.length,
            secretBox.nonce.length + secretBox.cipherText.length,
            secretBox.cipherText,
          );
    payload.setRange(
      secretBox.nonce.length + secretBox.cipherText.length,
      payload.length,
      secretBox.mac.bytes,
    );

    final b64 = base64.encode(payload);
    final b64Bytes = ascii.encode(b64);

    // Base64 length
    data.setUint32(offset, b64Bytes.length, Endian.little);
    offset += 4;

    // Base64 payload
    buffer.setRange(offset, offset + b64Bytes.length, b64Bytes);

    return buffer;
  }

  /// Parses the header from bytes using [key] to decrypt metadata.
  static Future<EPageFileHeader> fromBytes(
    Uint8List bytes,
    SecretKey key,
  ) async {
    if (bytes.length != headerSize) {
      throw FormatException('Invalid header size: ${bytes.length}');
    }

    final data = ByteData.view(bytes.buffer);
    var offset = 0;

    // Magic
    final magicBytes = bytes.sublist(offset, offset + 8);
    final magic = ascii.decode(magicBytes).trimRight();
    if (magic != magicString) {
      throw FormatException('Invalid magic string: $magic');
    }
    offset += 8;

    // Version
    final version = data.getUint32(offset, Endian.little);
    offset += 4;
    if (version != currentVersion) {
      throw FormatException('Unsupported version: $version');
    }

    // Base64 length
    final b64Length = data.getUint32(offset, Endian.little);
    offset += 4;

    if (b64Length <= 0 || offset + b64Length > bytes.length) {
      throw FormatException('Invalid encrypted metadata length: $b64Length');
    }

    final b64Bytes = bytes.sublist(offset, offset + b64Length);
    final payload = base64.decode(ascii.decode(b64Bytes));

    final secretBox = _decodeSecretBox(payload);
    final decrypted = await _decryptMetadata(secretBox, key);

    final metadata = ByteData.view(decrypted.buffer);
    var metaOffset = 0;
    final pageSize = metadata.getUint32(metaOffset, Endian.little);
    metaOffset += 4;
    final logicalLength = metadata.getUint64(metaOffset, Endian.little);
    metaOffset += 8;
    final pageCount = metadata.getUint64(metaOffset, Endian.little);

    return EPageFileHeader(
      version: version,
      pageSize: pageSize,
      logicalLength: logicalLength,
      pageCount: pageCount,
    );
  }

  Future<SecretBox> _encryptMetadata(SecretKey key) async {
    final algorithm = Xchacha20.poly1305Aead();
    final metadata = _buildMetadataBytes();
    return algorithm.encrypt(
      metadata,
      secretKey: key,
      nonce: algorithm.newNonce(),
    );
  }

  static SecretBox _decodeSecretBox(Uint8List payload) {
    const nonceSize = 24;
    const tagSize = 16;
    if (payload.length < nonceSize + tagSize) {
      throw FormatException('Encrypted header payload too short');
    }
    final nonce = payload.sublist(0, nonceSize);
    final cipherText = payload.sublist(24, payload.length - tagSize);
    final macBytes = payload.sublist(payload.length - tagSize);
    return SecretBox(cipherText, nonce: nonce, mac: Mac(macBytes));
  }

  static Future<Uint8List> _decryptMetadata(
    SecretBox secretBox,
    SecretKey key,
  ) async {
    final algorithm = Xchacha20.poly1305Aead();
    try {
      return Uint8List.fromList(
        await algorithm.decrypt(secretBox, secretKey: key),
      );
    } catch (e) {
      throw FormatException('Failed to decrypt header metadata: $e');
    }
  }

  Uint8List _buildMetadataBytes() {
    final buffer = Uint8List(metadataPlaintextLength);
    final data = ByteData.view(buffer.buffer);
    var offset = 0;

    data.setUint32(offset, pageSize, Endian.little);
    offset += 4;

    data.setUint64(offset, logicalLength, Endian.little);
    offset += 8;

    data.setUint64(offset, pageCount, Endian.little);
    offset += 8;

    // Remaining bytes left as zeros for future use.
    return buffer;
  }
}
