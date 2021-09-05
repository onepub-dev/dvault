import 'dart:io';
import 'dart:typed_data';

import 'package:async/async.dart';
import 'package:dcli/dcli.dart';
import 'package:dvault/src/toc_entry.dart';
import 'package:dvault/src/util/exceptions.dart';
import 'package:encrypt/encrypt.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';

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
  late final engine = AESFastEngine();

  // AESFastEngine use a 16 byte block size.
  int get blockSize => engine.blockSize;

  /// returns the no. of bytes it wrote to [writeTo]
  Future<int> encrypt(String pathToFileToEncrypt, IOSink writeTo) async {
    // Create a CBC block cipher with AES, and initialize with key and IV

    final cbc = CBCBlockCipher(engine)
      ..init(true,
          ParametersWithIV(KeyParameter(key.bytes), iv.bytes)); // true=encrypt

    // Encrypt the plaintext block-by-block

    final encryptionBuffer = Uint8List(blockSize); // allocate space

    var bytesWritten = 0;
    final reader = ChunkedStreamReader(File(pathToFileToEncrypt).openRead());

    /// write the length of the original file so
    /// that when decrypting we can strip the padding added
    /// due to the block cipher requiring a fixed block size.
    var sizeData = _intAsByteList(stat(pathToFileToEncrypt).size);
    writeTo.add(sizeData);
    try {
      // final chunkSize = blockSize ~/ 8;
      while (true) {
        var data = await reader.readChunk(blockSize);

        if (data.isEmpty) {
          break;
        }

        if (data.length < blockSize) {
          pad(data, blockSize);
        }

        var dataAsList = Uint8List.fromList(data);
        if (_skipEncryption) {
          writeTo.add(dataAsList);
        } else {
          cbc.processBlock(dataAsList, 0, encryptionBuffer, 0);
          writeTo.add(encryptionBuffer);
        }
        bytesWritten += dataAsList.length;
      }
    } finally {
      await reader.cancel();
    }
    return bytesWritten;
  }

  Future<void> decrypt(String pathToEncryptedFile, IOSink writeTo) async {
    final reader = ChunkedStreamReader(File(pathToEncryptedFile).openRead());

    try {
      await decryptStream(ChunkedReader(reader), writeTo);
    } finally {
      await reader.cancel();
      await writeTo.close();
    }
  }

  void decryptEntry(TOCEntry entry, RandomAccessFile raf, IOSink writeTo) {}

  /// Decrypts [stream] writing the plain text results
  /// to [writeTo]
  Future<void> decryptStream(ByteReader reader, IOSink writeTo) async {
    // Create a CBC block cipher with AES, and initialize with key and IV

    final cbc = CBCBlockCipher(engine)
      ..init(false,
          ParametersWithIV(KeyParameter(key.bytes), iv.bytes)); // false=decrypt

    /// read the size of the original file so we
    /// can ignore the padding added due to the block cipher
    /// requirement that all blocks are the same size.
    var sizeList = await reader.readChunk(8);
    if (sizeList.length != 8) {
      throw ArgumentError(
          'Unexpected file size. The stored file length was incomplete.');
    }

    var originalFileLength = _byteListAsInt(Uint8List.fromList(sizeList));

    // final chunkSize = blockSize ~/ 8;
    var plainTextBuffer = Uint8List(blockSize); // allocate space

    var readSoFar = 0;

    try {
      while (true) {
        var encryptedData = await reader.readChunk(blockSize);

        if (encryptedData.isEmpty) {
          break;
        }

        if (encryptedData.length != blockSize) {
          throw ArgumentError(
              'Unexpected file size. Should be multiple of block length');
        }

        readSoFar += encryptedData.length;

        if (_skipEncryption) {
          plainTextBuffer.setAll(0, encryptedData);
        } else {
          cbc.processBlock(
              Uint8List.fromList(encryptedData), 0, plainTextBuffer, 0);
        }
        if (readSoFar > originalFileLength) {
          /// we have read the last block so we need to strip
          /// any block cipher padding.
          var paddingSize = readSoFar - originalFileLength;
          var dataSize = blockSize - paddingSize;

          plainTextBuffer = trim(plainTextBuffer, dataSize);
          assert(plainTextBuffer.length == dataSize);

          /// calculate the final size of the file we read.
          readSoFar = readSoFar - paddingSize;
        }

        writeTo.add(plainTextBuffer);
      }
    } finally {
      await reader.cancel();
    }
    assert(readSoFar == originalFileLength);
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
  Uint8List trim(Uint8List plainTextBuffer, int dataSize) {
    return Uint8List.view(plainTextBuffer.buffer, 0, dataSize);
  }

  /// Converts an into to byte list using big endian.
  /// We do this to ensure that a vault is cross platform.
  /// See [_byteListAsInt]
  Uint8List _intAsByteList(int value) {
    return Uint8List(8)..buffer.asByteData().setInt64(0, value, Endian.big);
  }

  /// Converts a byte list to an int.
  /// The [list] data must be in big endian format.
  /// See [_intAsByteList]
  int _byteListAsInt(Uint8List list) {
    return list.buffer.asByteData().getInt64(0, Endian.big);
  }
}

abstract class ByteReader {
  Future<List<int>> readChunk(int bytes);

  Future<void> cancel();
}

class RafReader implements ByteReader {
  RafReader(this.raf);

  RandomAccessFile raf;

  @override
  Future<List<int>> readChunk(int bytes) {
    var read = <int>[];

    for (var i = 0; i < bytes; i++) {
      var byte = raf.readByteSync();

      if (byte == -1) throw UnexpectedEndOfFileException();
      read.add(byte);
    }
    return Future.value(read);
  }

  @override
  Future<void> cancel() {
    /// NO-OP
    return Future.value(null);
  }
}

class ChunkedReader implements ByteReader {
  ChunkedReader(this.stream);
  ChunkedStreamReader<int> stream;

  @override
  Future<List<int>> readChunk(int bytes) {
    return stream.readChunk(bytes);
  }

  @override
  Future<void> cancel() {
    return stream.cancel();
  }
}
