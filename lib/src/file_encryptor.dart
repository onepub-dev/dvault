/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';
import 'dart:typed_data';

import 'package:async/async.dart';
import 'package:dcli/dcli.dart';
import 'package:encrypt/encrypt.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';

/// An AES CBC block encryptor suitable
/// for encrypting files with a symmetric key.
///
/// Instantiating a
///
/// The [FileEncryptor] encodes the length of
/// the file being encrypted as the first cipher
/// block so the original file length can be restored.
class FileEncryptor {
  FileEncryptor() {
    _init();
  }

  /// Used for testing when we want to suppress
  /// the actually encryption step.
  @visibleForTesting
  FileEncryptor.noEncryption() : _skipEncryption = true {
    _init();
  }

  void _init() {
    iv = IV.fromSecureRandom(blockSize);
    key = Key.fromSecureRandom(blockSize);
  }

  bool _skipEncryption = false;

  late final Key key;
  late final IV iv;
  late final engine = AESEngine();

  // AESFastEngine use a 16 byte block size.
  int get blockSize => engine.blockSize;

  /// Encrypts the content of [pathToFileToEncrypt]
  /// writing the encrypted contents to [writeTo].
  /// We start off by writing the original
  /// length of the file as the first cypher block.
  /// returns the no. of bytes it wrote to [writeTo]
  Future<int> encrypt(
    String pathToFileToEncrypt,
    RandomAccessFile writeTo,
  ) async {
    // Create a CBC block cipher with AES, and initialize with key and IV
    final cbc = CBCBlockCipher(engine)
      ..init(
        true,
        ParametersWithIV(KeyParameter(key.bytes), iv.bytes),
      ); // true=encrypt

    // Encrypt the plaintext block-by-block

    final encryptionBuffer = Uint8List(blockSize); // allocate space

    var bytesWritten = 0;
    final stream = File(pathToFileToEncrypt).openRead();
    try {
      final reader = ChunkedReader(ChunkedStreamReader(stream));

      /// write the length of the original file so
      /// that when decrypting we can strip the padding added
      /// due to the block cipher requiring a fixed block size.
      final sizeData = _intAsByteList(stat(pathToFileToEncrypt).size);
      writeTo.writeFromSync(sizeData);

      /// Now encrypt and write the contents of the file
      /// in chunks.
      try {
        // final chunkSize = blockSize ~/ 8;
        while (true) {
          final data = await reader.readChunk(blockSize);

          if (data.isEmpty) {
            break;
          }

          if (data.length < blockSize) {
            pad(data, blockSize);
          }

          final dataAsList = Uint8List.fromList(data);
          if (_skipEncryption) {
            writeTo.writeFromSync(dataAsList);
          } else {
            cbc.processBlock(dataAsList, 0, encryptionBuffer, 0);
            writeTo.writeFromSync(encryptionBuffer);
          }
          bytesWritten += dataAsList.length;
        }
      } finally {
        reader.cancel();
      }
    } finally {
      /// ensure the stream is drained otherwise the
      /// file will remain locked.
      // if (!waitFor(stream.isEmpty)) {
      //   waitFor(stream.drain());
      // }
    }
    return bytesWritten;
  }

  /// Decrypt the contents of [pathToEncryptedFile] saving the
  /// plain text content to [writeTo].
  Future<void> decrypt(String pathToEncryptedFile, IOSink writeTo) async {
    final reader = ChunkedStreamReader(File(pathToEncryptedFile).openRead());

    try {
      decryptFiieReader(ChunkedReader(reader), writeTo);
    } finally {
      await reader.cancel();
      await writeTo.close();
    }
  }

  /// Extracts a file entry from the encrypted byte stream [raf]
  /// starting from
  void decryptFileEntry(int offset, RandomAccessFile raf, IOSink writeTo) {
    raf.setPositionSync(offset);

    final reader = RafReader(raf);

    try {
      decryptFiieReader(reader, writeTo);
    } finally {
      reader.cancel();
    }
  }

  /// Decrypts an encrypted file from [reader] where the first
  /// cipher block contains the length of the file.
  /// The plain-text content is written
  /// to [writeTo]
  @visibleForTesting
  void decryptFiieReader(ByteReader reader, IOSink writeTo) async {
    // Create a CBC block cipher with AES, and initialize with key and IV

    final cbc = CBCBlockCipher(engine)
      ..init(
        false,
        ParametersWithIV(KeyParameter(key.bytes), iv.bytes),
      ); // false=decrypt

    /// read the size of the original file so we
    /// can ignore the padding added due to the block cipher
    /// requirement that all blocks are the same size.
    final sizeList = await reader.readChunk(8);
    if (sizeList.length != 8) {
      throw ArgumentError(
        'Unexpected file size. The stored file length was incomplete.',
      );
    }

    final originalFileLength = _byteListAsInt(Uint8List.fromList(sizeList));

    var readSoFar = 0;
    var more = true;
    while (more) {
      // final chunkSize = blockSize ~/ 8;
      var plainTextBuffer = Uint8List(blockSize); // allocate space

      final encryptedData = await reader.readChunk(blockSize);

      if (encryptedData.isEmpty) {
        break;
      }

      if (encryptedData.length != blockSize) {
        throw ArgumentError(
          'Unexpected file size. Should be multiple of block length',
        );
      }

      readSoFar += encryptedData.length;

      if (_skipEncryption) {
        plainTextBuffer.setAll(0, encryptedData);
      } else {
        cbc.processBlock(
          Uint8List.fromList(encryptedData),
          0,
          plainTextBuffer,
          0,
        );
      }
      if (readSoFar > originalFileLength) {
        /// we have read the last block so we need to strip
        /// any block cipher padding.
        final paddingSize = readSoFar - originalFileLength;
        final dataSize = blockSize - paddingSize;

        plainTextBuffer = trim(plainTextBuffer, dataSize);
        assert(plainTextBuffer.length == dataSize, 'plan text is wrong length');

        /// calculate the final size of the file we read.
        readSoFar = readSoFar - paddingSize;
        // we have read the entire file.
        more = false;
      }

      writeTo.add(plainTextBuffer);
    }
    assert(
      readSoFar == originalFileLength,
      'Mis-match with original file length',
    );
  }

  /// AES requires a fixed block size so we have to
  /// pad the final block before we encrypt it.
  void pad(List<int> data, int chunkSize) {
    for (var i = data.length; i < chunkSize; i++) {
      data.add(0);
    }
  }

  /// AES requires a fixed block size so we have to
  /// trim the final block after decryption to
  /// match the original file size.
  Uint8List trim(Uint8List plainTextBuffer, int dataSize) =>
      Uint8List.view(plainTextBuffer.buffer, 0, dataSize);

  /// Converts an int [value] into to byte list using big endian.
  /// We do this to ensure that a security box is cross platform.
  /// See [_byteListAsInt]
  Uint8List _intAsByteList(int value) =>
      Uint8List(8)..buffer.asByteData().setInt64(0, value);

  /// Converts a byte list to an int.
  /// The [list] data must be in big endian format.
  /// See [_intAsByteList]
  int _byteListAsInt(Uint8List list) => list.buffer.asByteData().getInt64(0);
}

abstract class ByteReader {
  Future<List<int>> readChunk(int bytes);

  Future<void> cancel();
}

class RafReader implements ByteReader {
  RafReader(this.raf);

  RandomAccessFile raf;

  @override
  Future<List<int>> readChunk(int bytes) async {
    final read = <int>[];

    for (var i = 0; i < bytes; i++) {
      final byte = raf.readByteSync();

      if (byte == -1) {
        break;
      }
      read.add(byte);
    }
    return read;
  }

  @override
  Future<void> cancel() async {
    /// NO-OP
  }
}

class ChunkedReader implements ByteReader {
  ChunkedReader(this.stream);
  ChunkedStreamReader<int> stream;

  @override
  Future<List<int>> readChunk(int bytes) async => stream.readChunk(bytes);

  @override
  Future<void> cancel() => stream.cancel();
}
