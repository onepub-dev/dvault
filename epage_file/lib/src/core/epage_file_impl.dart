import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../interface/backing_store.dart';
import '../interface/epage_file.dart';
import 'header.dart';
import 'page_manager.dart';

/// Implementation of [EPageFile].
class EPageFileImpl implements EPageFile {
  final BackingStore _store;
  final PageManager _pageManager;
  final EPageFileHeader _header;
  final SecretKey _key;
  bool _headerDirty = false;

  EPageFileImpl._(this._store, this._pageManager, this._header, this._key);

  /// Opens an [EPageFile].
  static Future<EPageFile> open(
    BackingStore store, {
    required SecretKey key,
    int cacheSize = 10,
  }) async {
    // 1. Read Header
    EPageFileHeader header;
    if (await store.length() == 0) {
      // New file, create default header
      // Default page size 4KB? Or should it be configurable?
      // For now hardcode 4096.
      header = EPageFileHeader.create(pageSize: EPageFile.defaultPageSize);
      await store.write(0, await header.toBytes(key));
    } else {
      final headerBytes = await store.read(0, EPageFileHeader.headerSize);
      header = await EPageFileHeader.fromBytes(headerBytes, key);
    }

    // Ensure pageCount matches the logical length.
    final payloadSize = header.pageSize - PageManager.overheadSize;
    final expectedPageCount = header.logicalLength == 0
        ? 0
        : (header.logicalLength + payloadSize - 1) ~/ payloadSize;
    if (header.pageCount != expectedPageCount) {
      header.pageCount = expectedPageCount;
      await store.write(0, await header.toBytes(key));
    }

    // 2. Initialize PageManager
    final pageManager = PageManager(store, key, header, cacheSize);

    return EPageFileImpl._(store, pageManager, header, key);
  }

  int _calculatePageCount(int logicalLength) {
    if (logicalLength == 0) {
      return 0;
    }
    return (logicalLength + _pageManager.payloadSize - 1) ~/
        _pageManager.payloadSize;
  }

  void _updateLogicalLength(int newLength) {
    if (newLength == _header.logicalLength) {
      return;
    }
    _header.logicalLength = newLength;
    _header.pageCount = _calculatePageCount(newLength);
    _headerDirty = true;
  }

  /// Read [count] bytes starting at [offset].
  @override
  Future<Uint8List> readAt(int offset, int count) async {
    if (offset < 0) {
      throw ArgumentError('Offset must be non-negative');
    }
    if (offset >= _header.logicalLength) {
      return Uint8List(0); // EOF
    }

    // Cap count to EOF
    if (offset + count > _header.logicalLength) {
      count = _header.logicalLength - offset;
    }

    final result = Uint8List(count);
    int bytesRead = 0;
    int currentOffset = offset;

    while (bytesRead < count) {
      final pageIndex = currentOffset ~/ _pageManager.payloadSize;
      final pageOffset = currentOffset % _pageManager.payloadSize;
      final bytesToRead = (count - bytesRead).clamp(
        0,
        _pageManager.payloadSize - pageOffset,
      );

      final pageData = await _pageManager.readPage(pageIndex);

      // Copy data
      result.setRange(
        bytesRead,
        bytesRead + bytesToRead,
        pageData.sublist(pageOffset, pageOffset + bytesToRead),
      );

      bytesRead += bytesToRead;
      currentOffset += bytesToRead;
    }

    return result;
  }

  /// Write [buffer] starting at [offset].
  @override
  Future<void> writeAt(int offset, Uint8List buffer) async {
    if (offset < 0) {
      throw ArgumentError('Offset must be non-negative');
    }

    int bytesWritten = 0;
    int currentOffset = offset;

    while (bytesWritten < buffer.length) {
      final pageIndex = currentOffset ~/ _pageManager.payloadSize;
      final pageOffset = currentOffset % _pageManager.payloadSize;
      final bytesToWrite = (buffer.length - bytesWritten).clamp(
        0,
        _pageManager.payloadSize - pageOffset,
      );

      // Read existing page if we are doing a partial write
      Uint8List pageData;
      if (pageOffset > 0 || bytesToWrite < _pageManager.payloadSize) {
        // We need to read the page first
        // But wait, if it's a new page beyond current length, readPage might return zeros or fail?
        // PageManager.readPage handles it (returns zeros for new pages).
        pageData = await _pageManager.readPage(pageIndex);
      } else {
        // We are overwriting the whole page, no need to read.
        pageData = Uint8List(_pageManager.payloadSize);
      }

      // Update page data
      pageData.setRange(
        pageOffset,
        pageOffset + bytesToWrite,
        buffer.sublist(bytesWritten, bytesWritten + bytesToWrite),
      );

      // Write back
      await _pageManager.writePage(pageIndex, pageData);

      bytesWritten += bytesToWrite;
      currentOffset += bytesToWrite;
    }

    // Update logical length if we extended the file
    if (currentOffset > _header.logicalLength) {
      _updateLogicalLength(currentOffset);
    }
  }

  @override
  Future<void> flush() async {
    // Flush dirty pages first
    await _pageManager.flush();
    // Then update header if needed
    if (_headerDirty) {
      await _store.write(0, await _header.toBytes(_key));
      _headerDirty = false;
    }
    await _store.flush();
  }

  @override
  Future<void> close() async {
    await flush();
    await _store.close();
  }

  @override
  Future<int> length() async {
    return _header.logicalLength;
  }

  @override
  Future<void> setLength(int length) async {
    if (length < 0) {
      throw ArgumentError('Length must be non-negative');
    }

    if (length == _header.logicalLength) {
      return;
    }

    final oldLength = _header.logicalLength;
    final oldPageCount = _calculatePageCount(oldLength);
    final newPageCount = _calculatePageCount(length);

    if (length < oldLength) {
      // Truncation
      if (length > 0) {
        final lastPageIndex = (length - 1) ~/ _pageManager.payloadSize;
        final offsetInPage = length % _pageManager.payloadSize;

        // Zero the remainder of the final partial page so old data
        // isn't visible if the file is later extended.
        if (offsetInPage != 0) {
          final pageData = await _pageManager.readPage(lastPageIndex);
          pageData.fillRange(offsetInPage, pageData.length, 0);
          await _pageManager.writePage(lastPageIndex, pageData);
        }
      }

      // Overwrite and drop any pages beyond the new end of file.
      for (var pageIndex = newPageCount; pageIndex < oldPageCount; pageIndex++) {
        await _pageManager.writePage(
          pageIndex,
          Uint8List(_pageManager.payloadSize),
        );
      }
    }

    _updateLogicalLength(length);
  }
  
  @override
  int get pageSize => _pageManager.pageSize;
}
