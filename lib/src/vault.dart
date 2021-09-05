import 'dart:async';
import 'dart:cli';
import 'dart:io';

import 'package:dcli/dcli.dart';
import 'package:dvault/src/file_encryptor.dart';
import 'package:dvault/src/table_of_content.dart';
import 'package:dvault/src/util/exceptions.dart';
import 'package:dvault/src/util/raf_helper.dart';
import 'package:dvault/src/version/version.dart';

import 'dot_vault_file.dart';

/// Class for reading and writing vaults
/// A vault consists of serveral areas
///```
///magic: <magic code>
///version: x
///created: by DVault Version x.x.x.
///author: S. Brett Sutton
///<clear text public key>
///<encrypted private key>
///Ctrl-Z
///<64bit offset from SOF to the begining of the TOC>
///<Encrypted file data>
///<Table of Contents (TOC)>
//```
class VaultFile {
  TableOfContents toc = TableOfContents();

  VaultFile();

  /// This value must never be changed even across versions
  /// of DVault and
  static final MAGIC_CODE = '17e64d12-c347-4c67-9899-f52b015183ec';
  void saveTo(String pathToVault) {
    final dotVaultFile = DotVaultFile.load();
    pathToVault.append(_magicLine);
    pathToVault.append(_versionLine);
    pathToVault.append(_createdByLine);
    pathToVault.append(_authorLine);
    pathToVault.append(_saltLine(dotVaultFile.salt));
    pathToVault.append(_IVLine(dotVaultFile.iv));
    pathToVault
        .append(dotVaultFile.extractPrivateKeyLines().join(Platform().eol));
    pathToVault
        .append(dotVaultFile.extractPublicKeyLines().join(Platform().eol));
    pathToVault.append('');

    var startOfFiles = stat(pathToVault).size;
    waitFor(_saveFiles(pathToVault, startOfFiles));
    var startOfTOC = stat(pathToVault).size + 1;
    toc.saveToc(pathToVault);
    pathToVault.append(_startOfFilesLine(startOfFiles));
    pathToVault.append(_startOfTocLine(startOfTOC));
  }

  VaultFile.load(String pathToVault) {
    var vault = File(pathToVault);
    final file = waitFor(vault.open(mode: FileMode.read));
    _readMagic(pathToVault, file);
    _readVersion(pathToVault, file);
    _readCreatedBy(pathToVault, file);
    _readAuthor(pathToVault, file);
    _readSalt(pathToVault, file);
    _readIV(pathToVault, file);
    _readPrivateKey(pathToVault, file);
    _readPublicKey(pathToVault, file);

    toc = _loadToc(pathToVault, file);
    _extractFiles(pathToVault, file);

    waitFor(file.close());
  }

  int get version => 1;
  String get _magicLine => 'magic: $MAGIC_CODE';
  String get _versionLine => 'version: $version';
  String get _createdByLine => 'created: by DVault Version $packageVersion';
  String get _authorLine => 'author: S. Brett Sutton';

  String _saltLine(String salt) => 'salt: $salt';
  String _IVLine(String iv) => 'iv: $iv';

  /// The start of toc and start of files lines
  /// a re fixed width as we need be able to seek directly
  /// to them at the end of the file.
  String _startOfFilesLine(int startOfFiles) =>
      '$_startOfFilesPrefix $startOfFiles'.padRight(80);
  String _startOfTocLine(int startOfToc) =>
      '$_startOfTocPrefix $startOfToc'.padRight(80);

  String get _startOfTocPrefix => 'start of toc:';

  String get _startOfFilesPrefix => 'start of files:';

  TableOfContents _loadToc(String pathToVault, RandomAccessFile raf) {
    var length = raf.lengthSync();

    raf.setPositionSync(length - 162);
    var startOfFiles = _loadStartOfFiles(pathToVault, raf);
    var startOfToc = _loadStartOfToc(pathToVault, raf);

    return TableOfContents()
      ..load(startOfToc, raf)
      ..setStartOfFiles(startOfFiles);
  }

  void _readMagic(String pathToVault, RandomAccessFile file) {
    var magic = readLine(file, 'Magic');
    if (!_compareLine(magic, _magicLine)) {
      throw VaultReadException(
          'Unexpected Magic Code. Are you sure ${truepath(pathToVault)} is a vault?');
    }
  }

  void _readVersion(String pathToVault, RandomAccessFile file) {
    var version = readLine(file, 'Version');
    if (version.substring(0, version.length - 1) != _versionLine) {
      throw VaultReadException(
          'Unexpected Version. Expected $_versionLine, found $version');
    }
  }

  void _readCreatedBy(String pathToVault, RandomAccessFile file) {
    var createdBy = readLine(file, 'created');
    if (!createdBy.startsWith('created:')) {
      throw VaultReadException(
          'Unexpected Created. Expected $_createdByLine, found $createdBy');
    }
  }

  void _readAuthor(String pathToVault, RandomAccessFile file) {
    var author = readLine(file, 'Author');
    if (author.substring(0, author.length - 1) != _authorLine) {
      throw VaultReadException(
          'Unexpected Author. Expected $_authorLine, found $author');
    }
  }

  int _loadStartOfToc(String pathToVault, RandomAccessFile file) {
    var startOfToc = readLine(file, _startOfTocPrefix);
    if (!startOfToc.startsWith(_startOfTocPrefix)) {
      throw VaultReadException(
          'Unexpected Start of TOC Prefix. Expected $_startOfTocPrefix, found $startOfToc');
    }
    return parseNo(startOfToc, _startOfTocPrefix);
  }

  int _loadStartOfFiles(String pathToVault, RandomAccessFile file) {
    var startOfFiles = readLine(file, _startOfFilesPrefix);
    if (!startOfFiles.startsWith(_startOfFilesPrefix)) {
      throw VaultReadException(
          'Unexpected Start of TOC Prefix. Expected $_startOfFilesPrefix, found $startOfFiles');
    }
    return parseNo(startOfFiles, _startOfFilesPrefix);
  }

  bool _compareLine(String line, String expectedString) {
    return (line.substring(0, line.length - 1) != expectedString);
  }

  void addFile(String pathTo) {
    toc.addFile(pathTo);
  }

  Future<void> _saveFiles(String pathToVault, int startOfFiles) async {
    await toc.saveFiles(pathToVault, startOfFiles);
  }

  void addDirectory(String filePath, {required bool recursive}) {
    toc.addDirectory(filePath, recursive: recursive);
  }

  List<String> _readPrivateKey(String pathToVault, RandomAccessFile file) {
    var lines = <String>[];
    lines.add(readLine(file, 'Private Key Line 1'));
    lines.add(readLine(file, 'Private Key Line 2'));
    lines.add(readLine(file, 'Private Key Line 3'));
    return lines;
  }

  List<String> _readPublicKey(String pathToVault, RandomAccessFile file) {
    var lines = <String>[];
    lines.add(readLine(file, 'Public Key Line 1'));
    lines.add(readLine(file, 'Public Key Line 2'));
    lines.add(readLine(file, 'Public Key Line 3'));
    lines.add(readLine(file, 'Public Key Line 4'));

    return lines;
  }

  void _extractFiles(
      String pathToVault, RandomAccessFile raf, FileEncryptor fileEncryptor) {
    for (var entry in toc.entries) {
      raf.setPosition(entry.offset);

      withTempDir((dir) {
        var pathToExtractedFile = join(dir, entry.path);

        var writeTo = File(pathToExtractedFile).openWrite();
        fileEncryptor.decryptEntry(entry, raf, writeTo);
      }, keep: true);
    }
  }
}
