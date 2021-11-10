import 'dart:io';

import 'package:dcli/dcli.dart';
import 'package:dvault/src/util/raf_helper.dart';

import 'file_encryptor.dart';
import 'toc_entry.dart';

class TableOfContents {
  TableOfContents();

  List<TOCEntry> entries = <TOCEntry>[];

  void addFile({required String pathToFile, required String relativeTo}) {
    entries.add(TOCEntry(pathToFile: pathToFile, relativeTo: relativeTo));
  }

  void addDirectory({
    required String pathTo,
    required String relativeTo,
    bool recursive = false,
  }) {
    final types = [Find.file];
    if (recursive) {
      types.add(Find.directory);
    }
    find('*', workingDirectory: pathTo, recursive: recursive, types: types)
        .forEach((path) {
      if (isFile(path)) {
        entries.add(TOCEntry(pathToFile: path, relativeTo: relativeTo));
      }
    });
  }

  void saveFiles(FileSync vault, int startOfFiles) {
    final encryptor = FileEncryptor();

    // inal vaultSink = File(pathToVault).openWrite(mode: FileMode.append);

    var offset = startOfFiles;
    for (final entry in entries) {
      entry.length = addFileToVault(vault, entry, encryptor);
      entry.offset = offset;
      offset += entry.length;
    }

    //await vaultSink.close();
  }

  int addFileToVault(
    FileSync vault,
    TOCEntry entry,
    FileEncryptor encryptor,
  ) {
    return encryptor.encrypt(
      join(entry.relativeTo!, entry.relativePathToFile),
      vault,
    );
  }

  String get _tocEntryCountLine => 'entries:${entries.length}';

  void saveToc(FileSync vault) {
    vault.append(_tocEntryCountLine);
    for (final entry in entries) {
      vault.append(entry.asLine);
    }
  }

  /// Load the table of contents from [raf] starting
  /// at position [startOfToc]
  void load(int startOfToc, RandomAccessFile raf) {
    raf.setPositionSync(startOfToc);

    final entryCount = parseNo(readLine(raf, 'entries'), 'entries');

    for (var i = 0; i < entryCount; i++) {
      final entry = TOCEntry.fromLine(readLine(raf, 'offset'));
      entries.add(entry);
    }
  }

  // // ignore: unused_field
  // int? _startOfFiles;

  // // ignore: avoid_setters_without_getters
  // set setStartOfFiles(int startOfFiles) => _startOfFiles = startOfFiles;
}
