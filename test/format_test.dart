import 'dart:typed_data';

import 'package:dvault/src/lockbox/file_entry.dart';
import 'package:dvault/src/lockbox/lockbox_format.dart';
import 'package:dvault/src/lockbox/lockbox_header.dart';
import 'package:dvault/src/lockbox/lockbox_toc.dart';
import 'package:dvault/src/lockbox/recipient.dart';
import 'package:test/test.dart';

void main() {
  group('LockboxFormat', () {
    test('constants are correct', () {
      expect(
        LockboxFormat.magicBytes,
        equals([0x44, 0x56, 0x41, 0x55, 0x4C, 0x54]),
      );
      expect(LockboxFormat.version, equals(1));
      expect(LockboxFormat.minHeaderSize, equals(26));
      expect(LockboxFormat.defaultPageSize, equals(64 * 1024));
      expect(LockboxFormat.nonceSize, equals(12));
      expect(LockboxFormat.authTagSize, equals(16));
      expect(LockboxFormat.pageOverhead, equals(28));
      expect(LockboxFormat.firstFilePage, equals(1));
    });
  });

  group('LockboxHeader', () {
    test('serializes and deserializes correctly', () {
      final keyId = Uint8List.fromList(List.generate(16, (i) => i));
      final encryptedKey = Uint8List.fromList(List.generate(32, (i) => i));

      final recipient = Recipient(
        type: RecipientType.password,
        keyId: keyId,
        encryptedSessionKey: encryptedKey,
      );

      final header = LockboxHeader(
        version: LockboxFormat.version,
        pageSize: 65536,
        tocOffset: 1024,
        recipients: [recipient],
      );

      final bytes = header.toBytes();
      // Header size = Fixed (26) + Recipient (1 + 4 + 16 + 4 + 32 = 57) = 83
      expect(bytes.length, equals(83));

      final parsed = LockboxHeader.fromBytes(bytes);
      expect(parsed.version, equals(header.version));
      expect(parsed.pageSize, equals(header.pageSize));
      expect(parsed.tocOffset, equals(header.tocOffset));
      expect(parsed.recipients.length, equals(1));
      expect(parsed.recipients.first.type, equals(RecipientType.password));
      expect(parsed.recipients.first.keyId, equals(keyId));
      expect(parsed.recipients.first.encryptedSessionKey, equals(encryptedKey));
    });

    test('rejects invalid magic bytes', () {
      final badBytes = Uint8List(64);
      badBytes.setRange(0, 6, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

      expect(
        () => LockboxHeader.fromBytes(badBytes),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects invalid version', () {
      final badBytes = Uint8List(64);
      badBytes.setRange(0, 6, LockboxFormat.magicBytes);
      final data = ByteData.view(badBytes.buffer);
      data.setUint16(6, 99, Endian.little); // Invalid version

      expect(
        () => LockboxHeader.fromBytes(badBytes),
        throwsA(isA<FormatException>()),
      );
    });

    test('handles custom page sizes', () {
      final recipient = Recipient(
        type: RecipientType.password,
        keyId: Uint8List(16),
        encryptedSessionKey: Uint8List(32),
      );

      final header = LockboxHeader(
        version: LockboxFormat.version,
        pageSize: 128 * 1024, // 128KB
        tocOffset: 2048,
        recipients: [recipient],
      );

      final bytes = header.toBytes();
      final parsed = LockboxHeader.fromBytes(bytes);

      expect(parsed.pageSize, equals(128 * 1024));
    });
  });

  group('DVaultTOC', () {
    test('serializes and deserializes empty TOC', () {
      final toc = LockboxTOC();
      final bytes = toc.toBytes();

      final parsed = LockboxTOC.fromBytes(bytes);
      expect(parsed.files, isEmpty);
    });

    test('serializes and deserializes TOC with files', () {
      final toc = LockboxTOC();
      toc.files['file1.txt'] = FileEntry(
        path: 'file1.txt',
        offset: 0,
        length: 100,
        created: 1234567890,
        modified: 1234567891,
      );
      toc.files['dir/file2.txt'] = FileEntry(
        path: 'dir/file2.txt',
        offset: 100,
        length: 200,
        created: 1234567892,
        modified: 1234567893,
      );

      final bytes = toc.toBytes();
      final parsed = LockboxTOC.fromBytes(bytes);

      expect(parsed.files.length, equals(2));
      expect(parsed.files['file1.txt']?.path, equals('file1.txt'));
      expect(parsed.files['file1.txt']?.offset, equals(0));
      expect(parsed.files['file1.txt']?.length, equals(100));
      expect(parsed.files['dir/file2.txt']?.path, equals('dir/file2.txt'));
      expect(parsed.files['dir/file2.txt']?.offset, equals(100));
      expect(parsed.files['dir/file2.txt']?.length, equals(200));
    });

    test('handles large file paths', () {
      final toc = LockboxTOC();
      final longPath = 'a' * 500; // 500 character path
      toc.files[longPath] = FileEntry(
        path: longPath,
        offset: 0,
        length: 1,
        created: 0,
        modified: 0,
      );

      final bytes = toc.toBytes();
      final parsed = LockboxTOC.fromBytes(bytes);

      expect(parsed.files[longPath]?.path, equals(longPath));
    });

    test('handles many files', () {
      final toc = LockboxTOC();
      for (int i = 0; i < 1000; i++) {
        toc.files['file$i.txt'] = FileEntry(
          path: 'file$i.txt',
          offset: i * 100,
          length: 100,
          created: i,
          modified: i,
        );
      }

      final bytes = toc.toBytes();
      final parsed = LockboxTOC.fromBytes(bytes);

      expect(parsed.files.length, equals(1000));
      expect(parsed.files['file500.txt']?.offset, equals(50000));
    });

    test('handles unicode file names', () {
      final toc = LockboxTOC();
      toc.files['日本語.txt'] = FileEntry(
        path: '日本語.txt',
        offset: 0,
        length: 100,
        created: 0,
        modified: 0,
      );
      toc.files['emoji_😀.txt'] = FileEntry(
        path: 'emoji_😀.txt',
        offset: 100,
        length: 50,
        created: 0,
        modified: 0,
      );

      final bytes = toc.toBytes();
      final parsed = LockboxTOC.fromBytes(bytes);

      expect(parsed.files['日本語.txt']?.path, equals('日本語.txt'));
      expect(parsed.files['emoji_😀.txt']?.path, equals('emoji_😀.txt'));
    });
  });
}
