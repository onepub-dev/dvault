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

import 'toc_entry.dart';

/// An AES CBC block encryptor suitable
/// for encrypting files with a symetric key.
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

  /// returns the no. of bytes it wrote to [writeTo]
  int encrypt(String pathToFileToEncrypt, FileSync writeTo) {
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
      try {
        // final chunkSize = blockSize ~/ 8;
        while (true) {
          final data = reader.readChunk(blockSize);

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

  Future<void> decrypt(String pathToEncryptedFile, IOSink writeTo) async {
    final reader = ChunkedStreamReader(File(pathToEncryptedFile).openRead());

    try {
      decryptReader(ChunkedReader(reader), writeTo);
    } finally {
      await reader.cancel();
      await writeTo.close();
    }
  }

  void decryptEntry(
    TOCEntry entry,
    RandomAccessFile raf,
    IOSink writeTo,
  ) {
    final reader = RafReader(raf);

    try {
      decryptReader(reader, writeTo);
    } finally {
      reader.cancel();
    }
  }

  /// Decrypts [reader] writing the plain text results
  /// to [writeTo]
  void decryptReader(ByteReader reader, IOSink writeTo) {
    // Create a CBC block cipher with AES, and initialize with key and IV

    final cbc = CBCBlockCipher(engine)
      ..init(
        false,
        ParametersWithIV(KeyParameter(key.bytes), iv.bytes),
      ); // false=decrypt

    /// read the size of the original file so we
    /// can ignore the padding added due to the block cipher
    /// requirement that all blocks are the same size.
    final sizeList = reader.readChunk(8);
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

      final encryptedData = reader.readChunk(blockSize);

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
        readSoFar == originalFileLength, 'Mis-match with original file length');
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

  /// Converts an into to byte list using big endian.
  /// We do this to ensure that a vault is cross platform.
  /// See [_byteListAsInt]
  Uint8List _intAsByteList(int value) =>
      Uint8List(8)..buffer.asByteData().setInt64(0, value);

  /// Converts a byte list to an int.
  /// The [list] data must be in big endian format.
  /// See [_intAsByteList]
  int _byteListAsInt(Uint8List list) => list.buffer.asByteData().getInt64(0);
}

abstract class ByteReader {
  List<int> readChunk(int bytes);

  void cancel();
}

class RafReader implements ByteReader {
  RafReader(this.raf);

  RandomAccessFile raf;

  @override
  List<int> readChunk(int bytes) {
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
  void cancel() {
    /// NO-OP
  }
}

class ChunkedReader implements ByteReader {
  ChunkedReader(this.stream);
  ChunkedStreamReader<int> stream;

  @override
  // ignore: discarded_futures
  List<int> readChunk(int bytes) => waitForEx(stream.readChunk(bytes));

  @override
  // ignore: discarded_futures
  void cancel() => waitForEx(stream.cancel());
}
