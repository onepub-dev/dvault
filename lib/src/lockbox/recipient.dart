import 'dart:typed_data';

/// Type of recipient for a lockbox
enum RecipientType {
  /// Public Key Infrastructure (RSA)
  pki(0),

  /// Password based (Legacy/Share)
  password(1);

  final int value;
  const RecipientType(this.value);

  static RecipientType fromValue(int value) {
    return RecipientType.values.firstWhere(
      (e) => e.value == value,
      orElse: () => throw FormatException('Unknown RecipientType: $value'),
    );
  }
}

/// Represents an authorized recipient of a lockbox
class Recipient {
  /// The type of recipient (PKI or Password)
  final RecipientType type;

  /// The ID of the key used to encrypt the session key.
  /// For PKI: SHA-256 hash of the Public Key.
  /// For Password: The salt used for key derivation.
  final Uint8List keyId;

  /// The encrypted session key.
  final Uint8List encryptedSessionKey;

  Recipient({
    required this.type,
    required this.keyId,
    required this.encryptedSessionKey,
  });

  /// Serializes the recipient to a byte list.
  Uint8List toBytes() {
    final keyIdLen = keyId.length;
    final encryptedKeyLen = encryptedSessionKey.length;

    // Size: Type(1) + KeyIdLen(4) + KeyId(N) + EncryptedKeyLen(4) + EncryptedKey(M)
    final size = 1 + 4 + keyIdLen + 4 + encryptedKeyLen;
    final buffer = Uint8List(size);
    final data = ByteData.view(buffer.buffer);
    int offset = 0;

    // Type
    data.setUint8(offset, type.value);
    offset += 1;

    // KeyId Length
    data.setUint32(offset, keyIdLen, Endian.little);
    offset += 4;

    // KeyId
    buffer.setRange(offset, offset + keyIdLen, keyId);
    offset += keyIdLen;

    // Encrypted Session Key Length
    data.setUint32(offset, encryptedKeyLen, Endian.little);
    offset += 4;

    // Encrypted Session Key
    buffer.setRange(offset, offset + encryptedKeyLen, encryptedSessionKey);
    offset += encryptedKeyLen;

    return buffer;
  }

  /// Parses a recipient from a byte list.
  /// Returns the recipient and the number of bytes read.
  static (Recipient, int) fromBytes(Uint8List bytes, int startOffset) {
    final data = ByteData.view(bytes.buffer);
    int offset = startOffset;

    // Type
    final typeVal = data.getUint8(offset);
    final type = RecipientType.fromValue(typeVal);
    offset += 1;

    // KeyId Length
    final keyIdLen = data.getUint32(offset, Endian.little);
    offset += 4;

    // KeyId
    final keyId = bytes.sublist(offset, offset + keyIdLen);
    offset += keyIdLen;

    // Encrypted Session Key Length
    final encryptedKeyLen = data.getUint32(offset, Endian.little);
    offset += 4;

    // Encrypted Session Key
    final encryptedSessionKey = bytes.sublist(offset, offset + encryptedKeyLen);
    offset += encryptedKeyLen;

    return (
      Recipient(
        type: type,
        keyId: keyId,
        encryptedSessionKey: encryptedSessionKey,
      ),
      offset - startOffset,
    );
  }
}
