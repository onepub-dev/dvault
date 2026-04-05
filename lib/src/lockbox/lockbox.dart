import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dvault/src/lockbox/file_entry.dart';
import 'package:dvault/src/lockbox/lockbox_env_page.dart';
import 'package:dvault/src/lockbox/lockbox_page_manager.dart';
import 'package:dvault/src/lockbox/recipient.dart';
import 'package:dvault/src/util/strong_key.dart';
import 'package:dvault/src/vfs/lock_box_reader.dart';
import 'package:dvault/src/vfs/lock_box_writer.dart';
import 'package:web/web.dart';

import 'lockbox_format.dart';
import 'lockbox_header.dart';
import 'lockbox_page.dart';
import 'lockbox_toc.dart';

/// Abstract base class for DVault repository implementations.
///
/// Platform-specific implementations:
/// - IORepository: CLI/VM using dart:io
/// - OPFSRepository: Browser using OPFS
/// - HttpRepository: Browser read-only using HTTP Range Requests
abstract class LockBox {
  late final SecretKey _key;
  late final LockBoxHeader _header;

  /// Contains the environment variables
  late final LockBoxEnvPage envPage;
  late LockBoxTOC _toc;
  bool _dirty = false;

  /// File extension for lockbox files
  static const String extension = 'lbox';

  // Protected constructor for subclasses
  LockBox();

  /// Platform-specific file I/O methods (to be implemented by subclasses)

  /// Read bytes from the vault file at the given offset
  Future<Uint8List> readBytesAt(int offset, int length);

  /// Write bytes to the vault file at the given offset
  Future<void> writeBytesAt(int offset, Uint8List data);

  /// Get the current file size
  Future<int> getFileSize();

  /// Truncate the file to the given length
  Future<void> truncateFile(int length);

  /// Close the underlying file handle
  Future<void> closeFile();

  /// Create a writer for the lockbox
  Future<LockBoxWriter> createWriter();

  /// Initialize the repository (called by subclass after opening file)
  Future<void> initialize({
    required SecretKey key,
    required LockBoxHeader header,
    required LockBoxEnvPage envPage,
    required LockBoxTOC toc,
  }) async {
    _key = key;
    _header = header;
    _toc = toc;
  }

  // Protected setter for subclasses
  set toc(LockBoxTOC value) => _toc = value;

  // Protected getters for subclasses
  SecretKey get key => _key;
  LockBoxHeader get header => _header;

  /// Open or create a Lockbox
  static Future<LockBox> createLockBox({
    required StrongKey strongKey,
    required LockBoxWriter writer,
    required LockBox Function() create,
    int pageSize = LockBoxFormat.defaultPageSize,
  }) async {
    final salt = StrongKey.generateSalt();
    final passwordKey = await strongKey.deriveSecretKey(salt: salt);
    final sessionKey = SecretKey(
      Uint8List.fromList(
        List.generate(32, (_) => Random.secure().nextInt(256)),
      ),
    );
    final encryptedSessionKey = await PageManager.wrapKey(
      sessionKey,
      passwordKey,
    );

    final recipient = Recipient(
      type: RecipientType.password,
      keyId: salt,
      encryptedSessionKey: encryptedSessionKey,
    );

    // Create initial header to calculate size
    final tempHeader = LockBoxHeader.LockBoxHeader(
      version: LockBoxFormat.version,
      pageSize: pageSize,
      tocOffset: 0,
      recipients: [recipient],
    );

    // Recalculate TOC offset
    final realHeaderSize = tempHeader.headerSize;
    final tocOffset = realHeaderSize + pageSize;

    // Write the header
    final header = LockBoxHeader.LockBoxHeader(
      version: LockBoxFormat.version,
      pageSize: pageSize,
      tocOffset: tocOffset,
      recipients: [recipient],
    );
    await header.write(writer);

    // Write Env Page (Page 0) directly after the header
    final envPage = LockBoxEnvPage.empty(
      header: header,
      sessionKey: sessionKey,
      // writer: writer,
    );
    await envPage.write(writer);

    final lockbox = create();

    final toc = LockBoxTOC();

    await lockbox.initialize(
      key: sessionKey,
      header: header,
      toc: toc,
      envPage: envPage,
    );
    return lockbox;
  }

  // Shared encryption/decryption logic (platform-agnostic)

  Future<void> close() async {
    if (_dirty) {
      await _flush();
    }
    await closeFile();
  }

  static Future<LockBox> readLockBox({
    required LockBoxReader reader,
    required StrongKey strongKey,
    required LockBox Function() create,
  }) async {
    final header = await LockBoxHeader.read(reader);

    // Decrypt Session Key
    // Find password recipient
    final recipient = header.recipients.firstWhere(
      (r) => r.type == RecipientType.password,
      orElse: () => throw Exception('No password recipient found'),
    );

    final salt = recipient.keyId;
    final passwordKey = await _deriveKey(strongKey, salt);
    final sessionKey = await _unwrapKey(
      recipient.encryptedSessionKey,
      passwordKey,
    );

    // Read Env Page (Page 0)
    final physicalPageSize = header.pageSize;

    final envPage = await LockBoxEnvPage.read(
      reader: reader,
      header: header,
      sessionKey: sessionKey,
    );

    final lockbox = create();
    await lockbox.initialize(
      key: sessionKey,
      header: header,
      toc: LockBoxTOC(),
      envPage: envPage,
    );

    await _readTOC(header, reader, physicalPageSize, sessionKey, lockbox);

    return lockbox;
  }

  // Read TOC
  static Future<void> _readTOC(
    LockBoxHeader header,
    LockBoxReader reader,
    int physicalPageSize,
    SecretKey sessionKey,
    LockBox lockbox,
  ) async {
    final fileSize = await reader.size();
    final tocLength = fileSize - header.tocOffset;

    if (tocLength > 0) {
      final tocBytes = BytesBuilder();
      // Calculate number of TOC pages?
      // Or just read until EOF?
      // The TOC is stored as a sequence of pages.
      // We know the total length of the TOC area.

      var read = 0;
      // var pageIdx =
      //     (header.tocOffset - header.headerSize) ~/ physicalPageSize +
      //     LockBoxFormat.firstFilePage;

      while (read < tocLength) {
        final encryptedBytes = await reader.readBytesAt(
          header.tocOffset + read,
          physicalPageSize,
        );
        if (encryptedBytes.isEmpty) break;

        final decryptedPage = await LockBoxPage.decrypt(
          encryptedPage: encryptedBytes,
          key: sessionKey,
        );

        tocBytes.add(decryptedPage);
        read += encryptedBytes.length;
        // pageIdx++;
      }

      if (tocBytes.isNotEmpty) {
        lockbox.toc = LockBoxTOC.fromBytes(tocBytes.toBytes());
      }
    }
  }

  Future<void> _flush() async {
    if (!_dirty) return;

    final tocBytes = _toc.toBytes();

    int virtualStreamSize = 0;
    if (_toc.isNotEmpty) {
      final lastFile = _toc.lastFile;
      virtualStreamSize = lastFile.offset + lastFile.length;
    }

    final dataPageSize = _header.pageContentSize;
    final physicalPageSize = _header.pageSize;

    final totalFilePages =
        (virtualStreamSize + dataPageSize - 1) ~/ dataPageSize;
    final totalPhysicalFilePages = totalFilePages + LockBoxFormat.firstFilePage;
    final tocStartPhysicalOffset =
        _header.headerSize + (totalPhysicalFilePages * physicalPageSize);

    var currentTocOffset = 0;
    // var currentTocPageIdx = totalPhysicalFilePages;

    // Write TOC pages
    while (currentTocOffset < tocBytes.length) {
      final remaining = tocBytes.length - currentTocOffset;
      final toWrite = remaining < dataPageSize ? remaining : dataPageSize;

      final chunk = tocBytes.sublist(
        currentTocOffset,
        currentTocOffset + toWrite,
      );
      final paddedChunk = Uint8List(dataPageSize);
      paddedChunk.setRange(0, chunk.length, chunk);

      final encryptedPage = await LockBoxPage.encrypt(
        data: paddedChunk,
        key: _key,
        // pageIndex: currentTocPageIdx,
        pageSize: physicalPageSize,
      );

      final offset =
          tocStartPhysicalOffset +
          (currentTocOffset ~/ dataPageSize) * physicalPageSize;
      await writeBytesAt(offset, encryptedPage);

      currentTocOffset += toWrite;
      // currentTocPageIdx++;
    }

    // Truncate file to remove old TOC
    final newFileSize =
        tocStartPhysicalOffset +
        ((currentTocOffset + dataPageSize - 1) ~/ dataPageSize) *
            physicalPageSize;
    await truncateFile(newFileSize);

    // Update header
    final newHeader = LockBoxHeader.LockBoxHeader(
      version: _header.version,
      pageSize: _header.pageSize,
      tocOffset: tocStartPhysicalOffset,
      recipients: _header.recipients,
    );

    await writeBytesAt(0, newHeader.toBytes());
    _dirty = false;
  }

  // VFS Operations
  bool exists(String path) => _toc.exists(path);

  FileEntry? stat(String path) => _toc.stat(path);

  Future<Uint8List> read(String path) async {
    final entry = _toc.stat(path);
    if (entry == null) throw Exception('File not found: $path');

    final buffer = BytesBuilder();
    var currentOffset = entry.offset;
    var remaining = entry.length;

    while (remaining > 0) {
      final virtualPageSize = _header.pageSize;
      final physicalPageSize = _header.pageSize + LockBoxFormat.pageOverhead;

      final pageIdx = currentOffset ~/ virtualPageSize;
      final offsetInPage = currentOffset % virtualPageSize;
      final physicalPageIdx = pageIdx + LockBoxFormat.firstFilePage;
      final physicalOffset =
          _header.headerSize + (physicalPageIdx * physicalPageSize);

      final encryptedBytes = await readBytesAt(
        physicalOffset,
        physicalPageSize,
      );
      if (encryptedBytes.isEmpty) break;

      final decryptedPage = await LockBoxPage.decrypt(
        encryptedPage: encryptedBytes,
        key: _key,
        // pageIndex: physicalPageIdx,
      );

      final availableInPage = decryptedPage.length - offsetInPage;
      final toRead = remaining < availableInPage ? remaining : availableInPage;

      buffer.add(decryptedPage.sublist(offsetInPage, offsetInPage + toRead));

      currentOffset += toRead;
      remaining -= toRead;
    }

    return buffer.toBytes();
  }

  // TODO: we are decrypting and encryping on every write rather than just
  // encrypting when we need to flush.
  Future<void> addFile(String path, Uint8List fileContent) async {
    int startOffset = 0;
    if (_toc.isNotEmpty) {
      final lastFile = _toc.lastFile;
      startOffset = lastFile.offset + lastFile.length;
    }

    final length = fileContent.length;

    var written = 0;
    var currentOffset = startOffset;
    final dataPageSize = _header.pageContentSize;

    while (written < length) {
      final pageIndex = LockBoxPage.findPage(
        offset: currentOffset,
        header: header,
      );
      final page = await LockBoxPage.readPage(
        key: _key,
        pageIndex: pageIndex,
        header: _header,
        reader: this,
      );

      final offsetInPage = currentOffset % dataPageSize;
      final physicalPageIdx = pageIndex + LockBoxFormat.firstFilePage;

      if (offsetInPage > 0) {
        // Can only true for the first page of data we write
        final physicalOffset =
            _header.headerSize + (physicalPageIdx * _header.pageSize);

        final spaceInPage = dataPageSize - offsetInPage;
        final toWrite =
            (length - written) < spaceInPage ? (length - written) : spaceInPage;

        page.setContent(
          offsetInPage,
          fileContent.sublist(written, written + toWrite),
        );
        page.writePage(writer);

        written += toWrite;
        currentOffset += toWrite;
      }
    }

    _toc.append(
      path,
      FileEntry(
        path: path,
        offset: startOffset,
        length: length,
        created: DateTime.now().millisecondsSinceEpoch,
        modified: DateTime.now().millisecondsSinceEpoch,
      ),
    );

    _dirty = true;
    await _flush();
  }

  bool isDirectory(String path) => _toc.isDirectory(path);

  List<String> listFiles(String path, {bool recursive = false}) =>
      _toc.list(path, recursive: recursive);

  // Env Operations
  String? getEnv(String key) => envPage.getEnv(key);

  Future<void> setEnv(String key, String value) async {
    LockBoxWriter writer = await createWriter();
    envPage.setEnv(writer, key, value);
  }

  Map<String, String> listEnv() => envPage.listEnv();

  Future<void> delete(String path) async {
    if (!_toc.exists(path)) {
      throw Exception('File not found: $path');
    }
    _toc.remove(path);
    _dirty = true;
    await _flush();
  }

  Future<void> rename(String oldPath, String newPath) async {
    if (!_toc.exists(oldPath)) {
      throw Exception('File not found: $oldPath');
    }
    if (_toc.exists(newPath)) {
      throw Exception('File already exists: $newPath');
    }
    final entry = _toc.remove(oldPath)!;
    _toc.append(
      newPath,
      FileEntry(
        path: newPath,
        offset: entry.offset,
        length: entry.length,
        created: entry.created,
        modified: DateTime.now().millisecondsSinceEpoch,
      ),
    );
    _dirty = true;
    await _flush();
  }
}

// Key derivation and wrapping helpers
Future<SecretKey> _deriveKey(StrongKey strongKey, Uint8List salt) =>
    strongKey.deriveSecretKey(salt: salt);

Future<SecretKey> _unwrapKey(
  Uint8List encryptedSessionKey,
  SecretKey wrappingKey,
) => PageManager.unwrapKey(encryptedSessionKey, wrappingKey);
