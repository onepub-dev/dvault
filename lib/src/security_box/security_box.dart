/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dcli/dcli.dart';
import 'package:dcli_core/dcli_core.dart' as core;
import 'package:encrypt/encrypt.dart';
import 'package:path/path.dart';

import '../blob/blob_encryptor.dart';
import '../blob/file_blob_writer.dart';
import '../dot_vault_file.dart';
import '../file_encryptor.dart';
import '../util/exceptions.dart';
import '../util/raf_helper.dart';
import '../util/strong_key.dart';
import '../version/version.dart';
import 'table_of_content.dart';
import 'toc_entry.dart';

/// Class for reading and writing Security Boxes
/// A security box consists of serveral areas
///```
///magic: 17e64d12-c347-4c67-9899-f52b015183ec\n
///version: 1\n
///created: by DVault Version x.x.x.\n
///author: S. Brett Sutton\n
///salt: <base64 encoded salt>\n
///iv: <base 64 encoded iv>\n
///test: <test phrase used to validate passphrase>\n
///<clear text public key>\n
///<encrypted private key>\n
///Ctrl-Z\n
///<64bit offset from the start of file to the begining of the TOC>\n
///<Encrypted file data>
///<Encrypted Table of Contents (TOC)>
///start of file:xxxx
///start of toc:xxx
///```
/// The last two lines are both padded to 80 chars so we can
/// find their location by seeking back from the end of the file.

class SecurityBox {
  /// The width of each of the two last lines that begin
  /// with 'start of'....
  static const startOfLineLength = 80;

  /// the byte offset of the second last line that starts with
  /// 'start of file:'
  int startOfFileLineOffset(int fileLength) =>
      fileLength - (2 * (80 + '\n'.length)) + 1;

  /// the byte offset of the second last line that starts with
  /// 'start of toc:'
  int startOfTocLineOffset(int fileLength) =>
      fileLength - ((80 + '\n'.length)) + 1;

  /// Create a new security box ready to add files to.
  SecurityBox(this.pathToSecurityBox) {
    iv = IV.fromSecureRandom(16);
    salt = StrongKey.generateSalt;
  }

  // load the security box meta data.
  factory SecurityBox.load(String pathToSecurityBox) {
    final securityBox = SecurityBox._forLoading(pathToSecurityBox);
    // ignore: discarded_futures
    final raf = waitForEx(File(pathToSecurityBox).open());

    try {
      securityBox
        .._readMagic(raf)
        .._readVersion(raf)
        .._readCreatedBy(raf)
        .._readAuthor(raf)
        .._readSalt(raf)
        .._readIV(raf)
        .._readPrivateKey(raf)
        .._readPublicKey(raf)
        .._readCtrlZ(raf)
        ..toc = securityBox._loadToc(raf);
    } finally {
      // ignore: discarded_futures
      waitForEx(raf.close());
    }
    return securityBox;
  }

  /// Use this ctor when you are going to load an existing security box
  /// from disk
  SecurityBox._forLoading(this.pathToSecurityBox);

  /// This value must never be changed even across versions
  /// of DVault.
  static const magicCode = '17e64d12-c347-4c67-9899-f52b015183ec';
  int get version => 1;
  static const magicKey = 'magic';
  static const versionKey = 'version';
  static const createdKey = 'created';
  static const authorKey = 'author';
  static const saltKey = 'salt';
  static const ivKey = 'iv';
  static const startOfTocKey = 'start of toc';
  static const startOfFilesKey = 'start of files';

  TableOfContent toc = TableOfContent();

  String pathToSecurityBox;
  late final Uint8List salt;
  late final IV iv;

  String get _magicLine => '$magicKey:$magicCode';
  String get _versionLine => '$versionKey:$version';
  String get _createdByLine => '$createdKey:by DVault Version $packageVersion';
  String get _authorLine => '$authorKey:S. Brett Sutton';

  String get _ctrlZ => String.fromCharCode(26);

  /// Adds the file located at [pathTo] into the security boxes TOC
  /// index.
  /// The path of the file is converted to a path
  /// which is relative to [relativeTo]. If [relativeTo] is
  /// not passed then the current working directory is assumed.
  void addFileToIndex(String pathTo, {String? relativeTo}) {
    relativeTo ??= pwd;

    toc.indexFile(pathToFile: pathTo, relativeTo: relativeTo);
  }

  /// Adds the files in [pathToDirectory] to the security box's
  /// TOC index.
  /// If [recursive] is true then all files in subdirectories
  /// are also added.
  void addDirectoryToIndex({
    required String pathToDirectory,
    bool recursive = false,
    String? relativeTo,
  }) {
    relativeTo ??= pwd;
    toc.indexDirectory(
      pathTo: pathToDirectory,
      relativeTo: relativeTo,
      recursive: recursive,
    );
  }

  /// Createes the security box and encryptes/saves all files/diectories
  /// added to the TOC index.
  /// The security box is created at [pathToSecurityBox].
  /// If [remove] is true then we delete the files/directories
  /// as we add them to the security box.
  ///
  Future<void> create({bool remove = false}) async {
    final dotVaultFile = DotVaultFile.load();

    final encryptor = FileEncryptor();
    // final encryptor = FileEncryptor.noEncryption();
    await await core.withOpenFile(pathToSecurityBox, (securityBox) async {
      writeLine(securityBox, _magicLine);
      writeLine(securityBox, _versionLine);
      writeLine(securityBox, _createdByLine);
      writeLine(securityBox, _authorLine);
      writeLine(securityBox, _saltLine(dotVaultFile.salt));
      writeLine(securityBox, _ivLine(dotVaultFile.iv));
      // we include a copy of the user's private key encrypted
      // with their vault password.
      // This allows them to open the security box even if their
      // vault is deleted provided they know the vaults password.
      writeLine(securityBox, dotVaultFile.extractPrivateKeyLines().join('\n'));
      writeLine(securityBox, dotVaultFile.extractPublicKeyLines().join('\n'));
      writeLine(securityBox, _ctrlZ);

      final startOfFiles = securityBox.lengthSync();
      final directories = <String>{};
      // encrypt and write each file indexed in the TOC to the security box.
      await toc.content.forEach((tocEntry) {
        final originalPathToFile = tocEntry.originalPathToFile;
        if (!exists(originalPathToFile)) {
          print(orange('warning: skipped $originalPathToFile '
              'as it no longer exists'));
          return;
        }
        encryptor.encrypt(originalPathToFile, securityBox);
        directories.add(dirname(originalPathToFile));
        if (remove) {
          delete(originalPathToFile);
        }
      });

      if (remove) {
        for (final directory in directories) {
          if (isEmpty(directory)) {
            deleteDir(directory);
          }
        }
      }

      final startOfTOC = await securityBox.length();
      await toc.append(securityBox, encryptor);

      writeLine(securityBox, _startOfFilesLine(startOfFiles));
      writeLine(securityBox, _startOfTocLine(startOfTOC));
    });
  }

  void writeLine(RandomAccessFile raf, String line) {
    raf.writeStringSync('$line\n');
  }

  /// Extracts all files from the security box into [pathToExtractTo].
  ///```dart
  /// var securityBox = SecurityBox.load(pathToSecurityBox);
  /// securityBox.extractFiles();
  /// ```
  Future<void> loadFromDisk(String pathToExtractTo) async {
    // ignore: discarded_futures
    final raf = waitForEx(File(pathToSecurityBox).open());
    try {
      final fileEncryptor = BlobEncryptor();
      await toc.content.forEach((entry) async {
        await _extractFile(fileEncryptor, raf, entry, pathToExtractTo);
      });
    } finally {
      // ignore: discarded_futures
      waitForEx(raf.close());
    }
  }

  // void _saveFiles(
  //     FileSync securityBox, int startOfFiles, FileEncryptor encryptor) {
  //   toc.saveFiles(securityBox, startOfFiles, encryptor);
  // }

  String _saltLine(Uint8List salt) => '$saltKey:${base64Encode(salt)}';
  String _ivLine(IV iv) => '$ivKey:${iv.base64}';

  /// The start of toc and start of files lines
  /// are fixed width as we need be able to seek directly
  /// to them at the end of the file.
  String _startOfFilesLine(int startOfFiles) =>
      '\n$startOfFilesKey:$startOfFiles'.padRight(startOfLineLength);
  String _startOfTocLine(int startOfToc) =>
      '$startOfTocKey:$startOfToc'.padRight(startOfLineLength);

  /// decrypt the TOC from the security box
  /// and save it into a temp file.
  /// We use a temp file in case the TOC is
  /// very large.
  TableOfContent _loadToc(RandomAccessFile raf) {
    _loadStartOfFiles(raf);
    final startOfToc = _loadStartOfToc(raf);

    return TableOfContent()..load(startOfToc, raf);
  }

  void _readMagic(RandomAccessFile file) {
    final magic = readLine(file, 'Magic');
    if (magic != _magicLine) {
      throw SecurityBoxReadException(
        'Unexpected Magic Code. Are you sure '
        '${truepath(pathToSecurityBox)} is a security box?',
      );
    }
  }

  void _readVersion(RandomAccessFile file) {
    final version = readLine(file, versionKey);
    if (version != _versionLine) {
      throw SecurityBoxReadException(
        'Unexpected Version. Expected $_versionLine, found $version',
      );
    }
  }

  void _readCreatedBy(RandomAccessFile file) {
    final createdBy = readLine(file, createdKey);
    if (!createdBy.startsWith('created:')) {
      throw SecurityBoxReadException(
        'Unexpected Created. Expected $_createdByLine, found $createdBy',
      );
    }
  }

  void _readAuthor(RandomAccessFile file) {
    final author = readLine(file, authorKey);
    if (author != _authorLine) {
      throw SecurityBoxReadException(
        'Unexpected Author. Expected $_ivLine, found $author',
      );
    }
  }

  void _readSalt(RandomAccessFile file) {
    final _salt = readLine(file, saltKey);
    if (!_salt.startsWith('$saltKey:')) {
      throw SecurityBoxReadException(
        'Unexpected Salt. Expected $_saltLine, found $_salt',
      );
    }
    salt = base64Decode(_salt.substring(saltKey.length + 1));
  }

  void _readIV(RandomAccessFile file) {
    final _iv = readLine(file, saltKey);
    if (!_iv.startsWith('$ivKey:')) {
      throw SecurityBoxReadException(
        'Unexpected IV. Expected $_saltLine, found $_iv',
      );
    }
    iv = IV.fromBase64(_iv.substring(ivKey.length + 1));
  }

  void _readCtrlZ(RandomAccessFile file) {
    final ctrlZ = readLine(file, 'Ctrl-Z');
    if (ctrlZ != _ctrlZ) {
      throw SecurityBoxReadException(
        'Unexpected character. Expected Ctrl-Z, found $ctrlZ',
      );
    }
  }

  int _loadStartOfToc(RandomAccessFile raf) {
    final length = raf.lengthSync();
    raf.setPositionSync(startOfTocLineOffset(length));

    final startOfToc = readLine(raf, startOfTocKey);
    if (!startOfToc.startsWith(startOfTocKey)) {
      throw SecurityBoxReadException(
        'Unexpected Start of TOC Prefix. '
        'Expected $startOfTocKey, found $startOfToc',
      );
    }
    return parseNo(startOfToc, startOfTocKey);
  }

  int _loadStartOfFiles(RandomAccessFile raf) {
    final length = raf.lengthSync();
    raf.setPositionSync(startOfFileLineOffset(length));
    final startOfFiles = readLine(raf, startOfFilesKey);
    if (!startOfFiles.startsWith(startOfFilesKey)) {
      throw SecurityBoxReadException(
        'Unexpected Start of Files Prefix. '
        'Expected $startOfFilesKey, found $startOfFiles',
      );
    }
    return parseNo(startOfFiles, startOfFilesKey);
  }

  List<String> _readPrivateKey(RandomAccessFile file) {
    final lines = <String>[
      readLine(file, 'Private Key Line 1'),
      readLine(file, 'Private Key Line 2'),
      readLine(file, 'Private Key Line 3')
    ];
    return lines;
  }

  List<String> _readPublicKey(RandomAccessFile file) {
    final lines = <String>[
      readLine(file, 'Public Key Line 1'),
      readLine(file, 'Public Key Line 2'),
      readLine(file, 'Public Key Line 3'),
      readLine(file, 'Public Key Line 4')
    ];

    return lines;
  }

  /// Extracts [entry] from the security box saving the file with its original
  /// relative path into [extractToDirectory].
  Future<void> _extractFile(
    BlobEncryptor blobEncryptor,
    RandomAccessFile rafSecurityBox,
    TOCEntry entry,
    String extractToDirectory,
  ) async {
    final pathToExtractedFile =
        join(extractToDirectory, entry.relativePathToFile);

    final writeTo = FileBlobWriter(pathToExtractedFile);

    try {
      await blobEncryptor.decrypt(writeTo, rafSecurityBox);
    } finally {
      await writeTo.close();
    }
  }

  /// Extracts the file located at [startOffset] from the security box saving
  /// the file with its original
  /// relative path into [extractToPath].
  void _decryptRangeToFile(
    FileEncryptor fileEncryptor,
    RandomAccessFile rafSecurityBox,
    int startOffset,
    String extractToPath,
  ) {
    final writeTo = File(extractToPath).openWrite();

    try {
      rafSecurityBox.setPositionSync(startOffset);
      fileEncryptor.decryptFileEntry(startOffset, rafSecurityBox, writeTo);
    } finally {
      // ignore: discarded_futures
      waitForEx<void>(writeTo.close());
    }
  }
}
