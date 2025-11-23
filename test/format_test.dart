import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dvault/src/format/dvault_format.dart';
import 'package:dvault/src/format/dvault_header.dart';
import 'package:dvault/src/format/dvault_toc.dart';

void main() {
  group('DVaultFormat', () {
    test('constants are correct', () {
      expect(DVaultFormat.magicBytes, equals([0x44, 0x56, 0x41, 0x55, 0x4C, 0x54]));
      expect(DVaultFormat.version, equals(2));
      expect(DVaultFormat.headerSize, equals(64));
      expect(DVaultFormat.defaultPageSize, equals(64 * 1024));
      expect(DVaultFormat.nonceSize, equals(12));
      expect(DVaultFormat.authTagSize, equals(16));
      expect(DVaultFormat.pageOverhead, equals(28));
      expect(DVaultFormat.envPageCount, equals(1));
      expect(DVaultFormat.firstFilePage, equals(1));
    });
  });

  group('DVaultHeader', () {
    test('serializes and deserializes correctly', () {
      final salt = Uint8List.fromList(List.generate(16, (i) => i));
      final kdfParams = Uint8List.fromList(List.generate(16, (i) => i * 2));
      
      final header = DVaultHeader(
        version: DVaultFormat.version,
        pageSize: 65536,
        tocOffset: 1024,
        salt: salt,
        kdfParams: kdfParams,
      );

      final bytes = header.toBytes();
      expect(bytes.length, equals(DVaultFormat.headerSize));

      final parsed = DVaultHeader.fromBytes(bytes);
      expect(parsed.version, equals(header.version));
      expect(parsed.pageSize, equals(header.pageSize));
      expect(parsed.tocOffset, equals(header.tocOffset));
      expect(parsed.salt, equals(header.salt));
      expect(parsed.kdfParams, equals(header.kdfParams));
    });

    test('rejects invalid magic bytes', () {
      final badBytes = Uint8List(64);
      badBytes.setRange(0, 6, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      
      expect(
        () => DVaultHeader.fromBytes(badBytes),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects invalid version', () {
      final badBytes = Uint8List(64);
      badBytes.setRange(0, 6, DVaultFormat.magicBytes);
      badBytes[6] = 99; // Invalid version
      
      expect(
        () => DVaultHeader.fromBytes(badBytes),
        throwsA(isA<FormatException>()),
      );
    });

    test('handles custom page sizes', () {
      final header = DVaultHeader(
        version: DVaultFormat.version,
        pageSize: 128 * 1024, // 128KB
        tocOffset: 2048,
        salt: Uint8List(16),
        kdfParams: Uint8List(16),
      );

      final bytes = header.toBytes();
      final parsed = DVaultHeader.fromBytes(bytes);
      
      expect(parsed.pageSize, equals(128 * 1024));
    });
  });

  group('DVaultTOC', () {
    test('serializes and deserializes empty TOC', () {
      final toc = DVaultTOC();
      final bytes = toc.toBytes();
      
      final parsed = DVaultTOC.fromBytes(bytes);
      expect(parsed.files, isEmpty);
    });

    test('serializes and deserializes TOC with files', () {
      final toc = DVaultTOC();
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
      final parsed = DVaultTOC.fromBytes(bytes);

      expect(parsed.files.length, equals(2));
      expect(parsed.files['file1.txt']?.path, equals('file1.txt'));
      expect(parsed.files['file1.txt']?.offset, equals(0));
      expect(parsed.files['file1.txt']?.length, equals(100));
      expect(parsed.files['dir/file2.txt']?.path, equals('dir/file2.txt'));
      expect(parsed.files['dir/file2.txt']?.offset, equals(100));
      expect(parsed.files['dir/file2.txt']?.length, equals(200));
    });

    test('handles large file paths', () {
      final toc = DVaultTOC();
      final longPath = 'a' * 500; // 500 character path
      toc.files[longPath] = FileEntry(
        path: longPath,
        offset: 0,
        length: 1,
        created: 0,
        modified: 0,
      );

      final bytes = toc.toBytes();
      final parsed = DVaultTOC.fromBytes(bytes);

      expect(parsed.files[longPath]?.path, equals(longPath));
    });

    test('handles many files', () {
      final toc = DVaultTOC();
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
      final parsed = DVaultTOC.fromBytes(bytes);

      expect(parsed.files.length, equals(1000));
      expect(parsed.files['file500.txt']?.offset, equals(50000));
    });

    test('handles unicode file names', () {
      final toc = DVaultTOC();
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
      final parsed = DVaultTOC.fromBytes(bytes);

      expect(parsed.files['日本語.txt']?.path, equals('日本語.txt'));
      expect(parsed.files['emoji_😀.txt']?.path, equals('emoji_😀.txt'));
    });
  });
}
