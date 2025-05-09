/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:dcli/dcli.dart';
import 'package:dvault/src/security_box/toc_store.dart';
import 'package:path/path.dart';

import '../file_encryptor.dart';
import '../util/raf_helper.dart';
import 'toc_entry.dart';

class TableOfContent {
  TableOfContent();

  TOCStore tocStore = TOCStore();

  // List<TOCEntry> entries = <TOCEntry>[];

  // return a stream of the current [TOCEntry]s.
  Stream<TOCEntry> get content => tocStore.content;

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

  /// encrypt and save the toc to the [rafSecurityBox]
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
