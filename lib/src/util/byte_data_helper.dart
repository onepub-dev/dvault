import 'dart:typed_data';

/// Helper class for 64-bit integer operations that works in both VM and Web.
///
/// dart2js/ddc does not support [ByteData.getUint64] and [ByteData.setUint64].
/// This class provides a compatible implementation by splitting 64-bit integers
/// into two 32-bit integers.
class ByteDataHelper {
  /// Set a 64-bit unsigned integer at the specified [byteOffset].
  static void setUint64(
    ByteData data,
    int byteOffset,
    int value,
    Endian endian,
  ) {
    if (endian == Endian.little) {
      data.setUint32(byteOffset, value & 0xFFFFFFFF, Endian.little);
      data.setUint32(byteOffset + 4, (value >> 32) & 0xFFFFFFFF, Endian.little);
    } else {
      data.setUint32(byteOffset, (value >> 32) & 0xFFFFFFFF, Endian.big);
      data.setUint32(byteOffset + 4, value & 0xFFFFFFFF, Endian.big);
    }
  }

  /// Get a 64-bit unsigned integer from the specified [byteOffset].
  static int getUint64(ByteData data, int byteOffset, Endian endian) {
    if (endian == Endian.little) {
      final low = data.getUint32(byteOffset, Endian.little);
      final high = data.getUint32(byteOffset + 4, Endian.little);
      return (high << 32) | low;
    } else {
      final high = data.getUint32(byteOffset, Endian.big);
      final low = data.getUint32(byteOffset + 4, Endian.big);
      return (high << 32) | low;
    }
  }
}
