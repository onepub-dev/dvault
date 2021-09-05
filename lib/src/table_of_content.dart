import 'dart:io';

import 'package:dcli/dcli.dart';

import 'file_encryptor.dart';
import 'toc_entry.dart';

class TableOfContents {
  TableOfContents();

  List<TOCEntry> entries = <TOCEntry>[];

  void addFile(String pathTo) {
    entries.add(TOCEntry(pathTo));
  }

  void addDirectory(String pathTo, {bool recursive = false}) {
    var types = [Find.file];
    if (recursive) {
      types.add(Find.directory);
    }
    find('*', workingDirectory: pathTo, recursive: recursive, types: types)
        .forEach((path) {
      if (isFile(path)) {
        entries.add(TOCEntry(path));
      }
    });
  }

  Future<void> saveFiles(String pathToVault, int startOfFiles) async {
    var encryptor = FileEncryptor();

    final vaultSink = File(pathToVault).openWrite(mode: FileMode.append);

    var offset = startOfFiles;
    for (final entry in entries) {
      entry.length = await addFileToVault(vaultSink, entry.path, encryptor);
      entry.offset = offset;
      offset += entry.length;
    }

    await vaultSink.close();
  }

  Future<int> addFileToVault(
      IOSink vaultSink, String filePath, FileEncryptor encryptor) async {
    return await encryptor.encrypt(filePath, vaultSink);
  }

  String get _tocEntryCountLine => 'entries: ${entries.length}';

  void saveToc(String pathToVault) {
    pathToVault.append(_tocEntryCountLine);
    for (var entry in entries) {
      pathToVault.append(entry.asLine);
    }
  }

  /// Load the table of contents from [raf] starting
  /// at position [startOfToc]
  void load(int startOfToc, RandomAccessFile raf) {
    raf.setPositionSync(startOfToc);
  }


  int? _startOfFiles;
  void setStartOfFiles(int startOfFiles) => _startOfFiles = startOfFiles;
}
