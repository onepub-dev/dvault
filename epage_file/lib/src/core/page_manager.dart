import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../interface/backing_store.dart';
import 'header.dart';

/// Manages the reading and writing of pages, including encryption and caching.
class PageManager {
  final BackingStore _store;
  final SecretKey _key;
  final EPageFileHeader _header;
  final int _cacheSize;

  // LRU Cache for read pages (decrypted payload)
  final Map<int, Uint8List> _cache = {};
  final List<int> _lruList = []; // Most recently used at the end

  // Dirty pages that need to be written
  final Set<int> _dirtyPages = {};

  final _algorithm = Xchacha20.poly1305Aead();

  PageManager(this._store, this._key, this._header, this._cacheSize);

  int get pageSize => _header.pageSize;

  /// The size of the data payload in a page (Physical Page Size - Overhead).
  int get payloadSize => _header.pageSize - overheadSize;

  /// The overhead per page (Nonce + Tag).
  /// Nonce: 24 bytes (XChaCha20).
  /// Tag: 16 bytes.
  static const int nonceSize = 24;
  static const int tagSize = 16;
  static const int overheadSize = nonceSize + tagSize;

  /// Reads a page from the store, decrypts it, and returns the payload.
  Future<Uint8List> readPage(int pageIndex) async {
    // Check cache first
    if (_cache.containsKey(pageIndex)) {
      _touchPage(pageIndex);
      // Return a copy to prevent external modification
      return Uint8List.fromList(_cache[pageIndex]!);
    }

    // Calculate offset in backing store
    // Header + (PageIndex * PhysicalPageSize)
    final offset = EPageFileHeader.headerSize + (pageIndex * _header.pageSize);

    // Check if this page exists in the file
    final fileLength = await _store.length();
    if (offset >= fileLength) {
      // Page doesn't exist yet, return zeros
      final decryptedData = Uint8List(payloadSize);
      _addToCache(pageIndex, decryptedData);
      return Uint8List.fromList(decryptedData);
    }

    // Read raw encrypted page
    final encryptedData = await _store.read(offset, _header.pageSize);

    Uint8List decryptedData;
    if (encryptedData.length < _header.pageSize) {
      // Partial read (shouldn't happen if we checked length above)
      decryptedData = Uint8List(payloadSize);
    } else {
      // Decrypt
      decryptedData = await _decrypt(encryptedData);
    }

    // Add to cache
    _addToCache(pageIndex, decryptedData);

    // Return a copy
    return Uint8List.fromList(decryptedData);
  }

  /// Writes a page to the cache and marks it as dirty.
  /// Actual disk write happens on flush().
  Future<void> writePage(int pageIndex, Uint8List payload) async {
    if (payload.length != payloadSize) {
      // Pad if necessary
      if (payload.length < payloadSize) {
        final padded = Uint8List(payloadSize);
        padded.setRange(0, payload.length, payload);
        payload = padded;
      } else if (payload.length > payloadSize) {
        throw ArgumentError('Payload too large for page');
      }
    }

    // Add to cache and mark as dirty
    _addToCache(pageIndex, payload);
    _dirtyPages.add(pageIndex);
  }

  Future<Uint8List> _encrypt(Uint8List payload) async {
    // Generate random 24-byte nonce for XChaCha20
    final nonce = SecureRandom(nonceSize).bytes;

    final secretBox = await _algorithm.encrypt(
      payload,
      secretKey: _key,
      nonce: nonce,
    );

    final page = Uint8List(_header.pageSize);
    int offset = 0;

    // Layout: [Nonce] + [Ciphertext] + [Tag]

    // 1. Nonce
    page.setRange(offset, offset + nonceSize, nonce);
    offset += nonceSize;

    // 2. Ciphertext
    page.setRange(
      offset,
      offset + secretBox.cipherText.length,
      secretBox.cipherText,
    );
    offset += secretBox.cipherText.length;

    // 3. Tag
    page.setRange(offset, offset + tagSize, secretBox.mac.bytes);

    return page;
  }

  Future<Uint8List> _decrypt(Uint8List encryptedPage) async {
    int offset = 0;

    // 1. Nonce
    final nonce = encryptedPage.sublist(offset, offset + nonceSize);
    offset += nonceSize;

    // 2. Ciphertext
    final cipherTextLength = encryptedPage.length - nonceSize - tagSize;
    final cipherText = encryptedPage.sublist(offset, offset + cipherTextLength);
    offset += cipherTextLength;

    // 3. Tag
    final tag = encryptedPage.sublist(offset, offset + tagSize);

    final secretBox = SecretBox(cipherText, nonce: nonce, mac: Mac(tag));

    try {
      final decrypted = await _algorithm.decrypt(secretBox, secretKey: _key);
      return Uint8List.fromList(decrypted);
    } catch (e) {
      print('Decryption failed: $e');
      print('Nonce length: ${nonce.length}');
      print('Ciphertext length: ${cipherText.length}');
      print('Tag length: ${tag.length}');
      rethrow;
    }
  }

  /// Adds a page to the cache, evicting LRU page if necessary.
  void _addToCache(int pageIndex, Uint8List data) {
    final copy = Uint8List.fromList(data);

    // If already in cache, replace the stored data and refresh LRU.
    if (_cache.containsKey(pageIndex)) {
      _cache[pageIndex] = copy;
      _touchPage(pageIndex);
      return;
    }

    // Check if we need to evict
    if (_cache.length >= _cacheSize && _cacheSize > 0) {
      // Evict least recently used (first in list)
      final lruPage = _lruList.removeAt(0);
      _cache.remove(lruPage);
    }

    // Add to cache
    _cache[pageIndex] = copy;
    _lruList.add(pageIndex);
  }

  /// Marks a page as recently used by moving it to the end of LRU list.
  void _touchPage(int pageIndex) {
    _lruList.remove(pageIndex);
    _lruList.add(pageIndex);
  }

  /// Flushes all dirty pages to disk.
  Future<void> flush() async {
    for (final pageIndex in _dirtyPages) {
      final pageData = _cache[pageIndex];
      if (pageData != null) {
        final encryptedData = await _encrypt(pageData);
        final offset =
            EPageFileHeader.headerSize + (pageIndex * _header.pageSize);
        await _store.write(offset, encryptedData);
      }
    }
    _dirtyPages.clear();
    await _store.flush();
  }

  /// Removes cached/dirty pages from [pageIndex] (inclusive) onward.
  void discardPagesFrom(int pageIndex) {
    _cache.removeWhere((key, _) => key >= pageIndex);
    _dirtyPages.removeWhere((key) => key >= pageIndex);
    _lruList.removeWhere((key) => key >= pageIndex);
  }
}

class SecureRandom {
  static final Random _random = Random.secure();

  final Uint8List bytes;

  SecureRandom(int length) : bytes = Uint8List(length) {
    for (var i = 0; i < length; i++) {
      bytes[i] = _random.nextInt(256);
    }
  }
}
