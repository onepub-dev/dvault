/// Constants and types for the DVault format.
class LockBoxFormat {
  /// Magic bytes "DVAULT"
  static const List<int> magicBytes = [0x44, 0x56, 0x41, 0x55, 0x4C, 0x54];

  /// Current format version
  static const int version = 1;

  /// Minimum size of the header in bytes.
  /// Magic (6) + Version (2) + PageSize (4) + TOC Pointer (8) + HeaderSize (4) + RecipientCount (2) = 26 bytes
  static const int minHeaderSize = 26;

  /// Default page size (64KB)
  static const int defaultPageSize = 64 * 1024;

  /// Size of the Nonce/IV for AES-GCM / XChaCha20
  static const int nonceSize = 12; // Standard for AES-GCM

  /// Size of the Authentication Tag
  static const int authTagSize = 16;

  /// Overhead per page (Nonce + Tag)
  static const int pageOverhead = nonceSize + authTagSize;

  /// Page Index 0 is reserved for Environment Variables.
  static const int envPageCount = 1;
  static const int firstFilePage = envPageCount;
}
