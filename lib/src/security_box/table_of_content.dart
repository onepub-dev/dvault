/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:dcli/dcli.dart';

import '../file_encryptor.dart';
import '../util/raf_helper.dart';
import 'toc_entry.dart';

class TableOfContent {
  TableOfContent() : pathToTemporaryToc = createTempFilename();

  /// path to the toc entries.
  /// Each entr is stored as a single line.
  String pathToTemporaryToc;
  bool _open = false;

  // List<TOCEntry> entries = <TOCEntry>[];

  // Adds a file to the TOC index.
  // The file is not processed in any way
  void indexFile({required String pathToFile, required String relativeTo}) {
    _openFile();
    final tocEntry = TOCEntry(pathToFile: pathToFile, relativeTo: relativeTo);
    _writeTempTocEntry(tocEntry);
  }

  void _writeTempTocEntry(TOCEntry tocEntry) {
    pathToTemporaryToc.append(tocEntry.asLine);
  }

  void _openFile() {
    if (!_open) {
      _open = true;
    }
  }

  /// Adds all file contained in the directory [pathTo] to the TOC index.
  /// The files are not processed in any way.
  /// If [recursive] is true then all files in any subdirectories are
  /// also added.
  /// Hidden files will be ignored.
  void indexDirectory({
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
        pathToTemporaryToc
            .append(TOCEntry(pathToFile: path, relativeTo: relativeTo).asLine);
      }
    });
  }

  // return a stream of the current [TOCEntry]s.
  Stream<TOCEntry> get content =>
      read(pathToTemporaryToc).stream.map(TOCEntry.fromLine);

  // void saveFiles(
  //     FileSync securityBox, int startOfFiles, FileEncryptor encryptor) {
  //   var offset = startOfFiles;
  //   for (final entry in entries) {
  //     entry
  //       ..length = addFileToSecurityBox(securityBox, entry, encryptor)
  //       ..offset = offset;
  //     offset += entry.length;
  //   }
  // }

  int addFileToSecurityBox(
    RandomAccessFile securitBox,
    TOCEntry entry,
    FileEncryptor encryptor,
  ) =>
      encryptor.encrypt(
        join(entry.relativeTo!, entry.relativePathToFile),
        securitBox,
      );

  /// encrypts and writes the TOC index (list of TOCEntrys )  to [securityBox]
  Future<void> append(
      RandomAccessFile securityBox, FileEncryptor encryptor) async {
    encryptor.encrypt(
      pathToTemporaryToc,
      securityBox,
    );
  }

  // String get _tocEntryCountLine => 'entries:${entries.length}';

  /// encrypt and save the toc to the [securityBox]
  /// returning the length of the encrypted data
  // int append(FileSync securityBox, FileEncryptor encryptor) =>
  //     withTempFile((pathToTempToc) {
  //       // the no. of entries in the toc
  //       pathToTempToc.append(_tocEntryCountLine);
  //       // each toc to its own line
  //       for (final entry in entries) {
  //         pathToTempToc.append(entry.asLine);
  //       }
  //       return encryptor.encrypt(pathToTempToc, securityBox);
  //     });

  /// Load the table of contents from [rafSecurityBox] starting
  /// at position [startOfToc]
  void load(int startOfToc, RandomAccessFile rafSecurityBox) {
    withTempFile((pathToToc) {
      final writeTo = File(pathToToc).openWrite();
      try {
        FileEncryptor().decryptFileEntry(startOfToc, rafSecurityBox, writeTo);

        // ignore: discarded_futures
        final raf = waitForEx(File(pathToToc).open());

        try {
          final entryCount = parseNo(readLine(raf, 'entries'), 'entries');

          for (var i = 0; i < entryCount; i++) {
            final entry = TOCEntry.fromLine(readLine(raf, 'offset'));
            _writeTempTocEntry(entry);
          }
        } finally {
          // ignore: discarded_futures
          waitForEx(raf.close());
        }
      } finally {
        // ignore: discarded_futures
        waitForEx<void>(writeTo.close());
      }
    });
  }

  // // ignore: unused_field
  // int? _startOfFiles;

  // // ignore: avoid_setters_without_getters
  // set setStartOfFiles(int startOfFiles) => _startOfFiles = startOfFiles;
}
