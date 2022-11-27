/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dcli/dcli.dart';
import 'package:encrypt/encrypt.dart';

import 'dot_vault_file.dart';
import 'file_encryptor.dart';
import 'table_of_content.dart';
import 'toc_entry.dart';
import 'util/exceptions.dart';
import 'util/raf_helper.dart';
import 'util/strong_key.dart';
import 'version/version.dart';

/// Class for reading and writing vaults
/// A vault consists of serveral areas
///```
///magic: 17e64d12-c347-4c67-9899-f52b015183ec
///version: 1
///created: by DVault Version x.x.x.
///author: S. Brett Sutton
///salt: <base64 encoded salt>
///iv: <base 64 encoded iv>
///test: <test phrase used to validate passphrase>
///<clear text public key>
///<encrypted private key>
///Ctrl-Z
///<64bit offset from SOF to the begining of the TOC>
///<Encrypted file data>
///<Table of Contents (TOC)>
//```
class VaultFile {
  /// Create a new vault object ready to add files to.
  VaultFile(this.pathToVault) {
    iv = IV.fromSecureRandom(16);
    salt = StrongKey.generateSalt;
  }

  /// Use this ctor when you are going to load the vault from disk
  VaultFile._forLoading(this.pathToVault);
  TableOfContents toc = TableOfContents();

  String pathToVault;
  late final Uint8List salt;
  late final IV iv;

  /// This value must never be changed even across versions
  /// of DVault and
  static const magicCode = '17e64d12-c347-4c67-9899-f52b015183ec';

  /// Saves the added files and directories into the vault
  /// at [pathToVault]
  /// encrypting them (locking) as it goes.
  void saveTo() {
    final dotVaultFile = DotVaultFile.load();
    withOpenFile(pathToVault, (vault) {
      vault
        ..append(_versionLine)
        ..append(_magicLine)
        ..append(_createdByLine)
        ..append(_authorLine)
        ..append(_saltLine(dotVaultFile.salt))
        ..append(_ivLine(dotVaultFile.iv))
        ..append(dotVaultFile.extractPrivateKeyLines().join(Platform().eol))
        ..append(dotVaultFile.extractPublicKeyLines().join(Platform().eol))
        ..append('');
      final startOfFiles = vault.length;
      _saveFiles(vault, startOfFiles);
      final startOfTOC = vault.length;
      toc.saveToc(vault);
      vault
        ..append(_startOfFilesLine(startOfFiles))
        ..append(_startOfTocLine(startOfTOC));
    });
  }

  // ignore: prefer_constructors_over_static_methods
  static VaultFile load(String pathToVault) {
    // final vault = File(pathToVault);

    final vault = VaultFile._forLoading(pathToVault);
    // ignore: discarded_futures
    final raf = waitForEx(File(pathToVault).open());
    try {
      vault
        .._readMagic(pathToVault, raf)
        .._readVersion(pathToVault, raf)
        .._readCreatedBy(pathToVault, raf)
        .._readAuthor(pathToVault, raf)
        .._readSalt(pathToVault, raf)
        .._readIV(pathToVault, raf)
        .._readPrivateKey(pathToVault, raf)
        .._readPublicKey(pathToVault, raf)
        ..toc = vault._loadToc(pathToVault, raf);
    } finally {
      // ignore: discarded_futures
      waitForEx(raf.close());
    }
    return vault;
  }

  /// Extracts all files from the vault into [pathToExtractTo].
  ///```dart
  /// var vault = Vault.load(pathToVault);
  /// vault.extractFiles();
  /// ```
  void extractFiles(String pathToExtractTo) {
    // ignore: discarded_futures
    final raf = waitForEx(File(pathToVault).open());
    try {
      final fileEncryptor = FileEncryptor();
      for (final entry in toc.entries) {
        _extractFile(fileEncryptor, raf, entry, pathToExtractTo);
      }
    } finally {
      // ignore: discarded_futures
      waitForEx(raf.close());
    }
  }

  int get version => 1;
  static const magicKey = 'magic';
  static const versionKey = 'version';
  static const createdKey = 'created';
  static const authorKey = 'author';
  static const saltKey = 'salt';
  static const ivKey = 'iv';
  static const startOfTocKey = 'start of toc';
  static const startOfFilesKey = 'start of files';

  String get _magicLine => '$magicKey:$magicCode';
  String get _versionLine => '$versionKey:$version';
  String get _createdByLine => '$createdKey:by DVault Version $packageVersion';
  String get _authorLine => '$authorKey:S. Brett Sutton';

  String _saltLine(Uint8List salt) => '$saltKey:${base64Encode(salt)}';
  String _ivLine(IV iv) => '$ivKey:${iv.base64}';

  /// The start of toc and start of files lines
  /// a re fixed width as we need be able to seek directly
  /// to them at the end of the file.
  String _startOfFilesLine(int startOfFiles) =>
      '$startOfFilesKey:$startOfFiles'.padRight(80);
  String _startOfTocLine(int startOfToc) =>
      '$startOfTocKey:$startOfToc'.padRight(80);

  TableOfContents _loadToc(String pathToVault, RandomAccessFile raf) {
    final length = raf.lengthSync();

    raf.setPositionSync(length - (2 * (80 + Platform().eol.length)));
    _loadStartOfFiles(pathToVault, raf);
    final startOfToc = _loadStartOfToc(pathToVault, raf);

    return TableOfContents()..load(startOfToc, raf);
    // ..setStartOfFiles = startOfFiles;
  }

  void _readMagic(String pathToVault, RandomAccessFile file) {
    final magic = readLine(file, 'Magic');
    if (magic != _magicLine) {
      throw VaultReadException(
        'Unexpected Magic Code. Are you sure '
        '${truepath(pathToVault)} is a vault?',
      );
    }
  }

  void _readVersion(String pathToVault, RandomAccessFile file) {
    final version = readLine(file, versionKey);
    if (version != _versionLine) {
      throw VaultReadException(
        'Unexpected Version. Expected $_versionLine, found $version',
      );
    }
  }

  void _readCreatedBy(String pathToVault, RandomAccessFile file) {
    final createdBy = readLine(file, createdKey);
    if (!createdBy.startsWith('created:')) {
      throw VaultReadException(
        'Unexpected Created. Expected $_createdByLine, found $createdBy',
      );
    }
  }

  void _readAuthor(String pathToVault, RandomAccessFile file) {
    final author = readLine(file, authorKey);
    if (author != _authorLine) {
      throw VaultReadException(
        'Unexpected Author. Expected $_ivLine, found $author',
      );
    }
  }

  void _readSalt(String pathToVault, RandomAccessFile file) {
    final _salt = readLine(file, saltKey);
    if (!_salt.startsWith('$saltKey:')) {
      throw VaultReadException(
        'Unexpected Salt. Expected $_saltLine, found $_salt',
      );
    }
    salt = base64Decode(_salt.substring(saltKey.length + 1));
  }

  void _readIV(String pathToVault, RandomAccessFile file) {
    final _iv = readLine(file, saltKey);
    if (!_iv.startsWith('$ivKey:')) {
      throw VaultReadException(
        'Unexpected IV. Expected $_saltLine, found $_iv',
      );
    }
    iv = IV.fromBase64(_iv.substring(ivKey.length + 1));
  }

  int _loadStartOfToc(String pathToVault, RandomAccessFile file) {
    final startOfToc = readLine(file, startOfTocKey);
    if (!startOfToc.startsWith(startOfTocKey)) {
      throw VaultReadException(
        'Unexpected Start of TOC Prefix. '
        'Expected $startOfTocKey, found $startOfToc',
      );
    }
    return parseNo(startOfToc, startOfTocKey);
  }

  int _loadStartOfFiles(String pathToVault, RandomAccessFile file) {
    final startOfFiles = readLine(file, startOfFilesKey);
    if (!startOfFiles.startsWith(startOfFilesKey)) {
      throw VaultReadException(
        'Unexpected Start of TOC Prefix. '
        'Expected $startOfFilesKey, found $startOfFiles',
      );
    }
    return parseNo(startOfFiles, startOfFilesKey);
  }

  /// Adds the file located at [pathTo] into the vault
  /// The path of the file is converted to a path
  /// which is relative to [relativeTo]. If [relativeTo] is
  /// not passed then the current working directory is assumed.
  void addFile(String pathTo, {String? relativeTo}) {
    relativeTo ??= pwd;

    toc.addFile(pathToFile: pathTo, relativeTo: relativeTo);
  }

  void _saveFiles(FileSync vault, int startOfFiles) {
    toc.saveFiles(vault, startOfFiles);
  }

  void addDirectory({
    required String pathToDirectory,
    required bool recursive,
    String? relativeTo,
  }) {
    relativeTo ??= pwd;
    toc.addDirectory(
      pathTo: pathToDirectory,
      relativeTo: relativeTo,
      recursive: recursive,
    );
  }

  List<String> _readPrivateKey(String pathToVault, RandomAccessFile file) {
    final lines = <String>[
      readLine(file, 'Private Key Line 1'),
      readLine(file, 'Private Key Line 2'),
      readLine(file, 'Private Key Line 3')
    ];
    return lines;
  }

  List<String> _readPublicKey(String pathToVault, RandomAccessFile file) {
    final lines = <String>[
      readLine(file, 'Public Key Line 1'),
      readLine(file, 'Public Key Line 2'),
      readLine(file, 'Public Key Line 3'),
      readLine(file, 'Public Key Line 4')
    ];

    return lines;
  }

  /// Extracts [entry] from the vault saving the file with its original
  /// relative path into [extractToDirectory].
  void _extractFile(
    FileEncryptor fileEncryptor,
    RandomAccessFile rafVault,
    TOCEntry entry,
    String extractToDirectory,
  ) {
    final pathToExtractedFile =
        join(extractToDirectory, entry.relativePathToFile);

    final writeTo = File(pathToExtractedFile).openWrite();

    try {
      rafVault.setPositionSync(entry.offset);
      fileEncryptor.decryptEntry(entry, rafVault, writeTo);
    } finally {
      // ignore: discarded_futures
      waitForEx<void>(writeTo.close());
    }
  }
}
