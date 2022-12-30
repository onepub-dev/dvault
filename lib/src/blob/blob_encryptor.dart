/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';

import 'blob_reader.dart';
import 'blob_writer.dart';
import 'byte_reader.dart';
import 'raf_reader.dart';

/// An AES CBC block encryptor suitable
/// for encrypting blobs with a symmetric key.
///
/// The [BlobEncryptor] encodes the length of
/// the blob being encrypted as the first cypher
/// block. The contents of the blob are then
/// written as additional cypher blocks.
/// When decrypting a blob the length is obtain from
/// the first cipher block and then the remain blobs read/decrypted.
class BlobEncryptor {
  BlobEncryptor() : _skipEncryption = false {
    _init();
  }

  /// Used for testing when we want to suppress
  /// the actually encryption step.
  @visibleForTesting
  BlobEncryptor.noEncryption() : _skipEncryption = true {
    _init();
  }

  final bool _skipEncryption;

  late final Key key;
  late final IV iv;
  late final engine = AESEngine();

  // AESFastEngine use a 16 byte block size.
  int get blockSize => engine.blockSize;

  void _init() {
    iv = IV.fromSecureRandom(blockSize);
    key = Key.fromSecureRandom(blockSize);
  }

  /// Encrypts the content of [blob]
  /// writing the encrypted contents to [raf] at the current
  /// seek offset.
  /// We start off by writing the
  /// length of the blob as the first cipher block.
  /// Returns the no. of bytes it wrote to [raf] and
  /// the seek position is updated to point to the next byte
  /// after the last byte that we write.
  Future<int> encrypt(BlobReader blob, RandomAccessFile raf) async {
    // Create a CBC block cipher with AES, and initialize with key and IV
    final cbc = CBCBlockCipher(engine)
      ..init(
        true,
        ParametersWithIV(KeyParameter(key.bytes), iv.bytes),
      ); // true=encrypt

    // Encrypt the plaintext block-by-block

    final encryptionBuffer = Uint8List(blockSize); // allocate space

    var bytesWritten = 0;
    try {
      final length = await blob.length;

      /// write the length of the original file so
      /// that when decrypting we can strip the padding added
      /// due to the block cipher requiring a fixed block size.
      raf.writeFromSync(_intAsByteList(length));

      /// Now encrypt and write the contents of the file
      /// in chunks.
      try {
        while (true) {
          final data = await blob.read(blockSize);

          if (data.isEmpty) {
            break;
          }

          if (data.length < blockSize) {
            pad(data, blockSize);
          }

          final dataAsList = Uint8List.fromList(data);
          if (_skipEncryption) {
            raf.writeFromSync(dataAsList);
          } else {
            cbc.processBlock(dataAsList, 0, encryptionBuffer, 0);
            raf.writeFromSync(encryptionBuffer);
          }
          bytesWritten += dataAsList.length;
        }
      } finally {
        await blob.close();
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

  /// Extracts a Blob  from the encrypted byte stream [encryptedSourceRaf]
  /// reading from the current seek position of [encryptedSourceRaf].
  /// [dest] is the [BlobReader] to write the plain text data to.
  /// We return [dest] from this call as a convenience.
  Future<BlobWriter> decrypt(
    BlobWriter dest,
    RandomAccessFile encryptedSourceRaf,
  ) async {
    final reader = RafReader(encryptedSourceRaf);

    try {
      await decryptBlobFromReader(reader, dest);

      return dest;
    } finally {
      reader.cancel();
    }
  }

  /// Decrypts an encrypted file from [reader] where the first
  /// cipher block contains the length of the blob.
  /// The plain-text content is written
  /// to [dest]
  @visibleForTesting
  Future<void> decryptBlobFromReader(ByteReader reader, BlobWriter dest) async {
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

        /// calculate the final size of the blob we read.
        readSoFar = readSoFar - paddingSize;
        // we have read the entire blob.
        more = false;
      }

      await dest.write(plainTextBuffer);
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
