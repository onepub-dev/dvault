import 'package:dcli/dcli.dart';
import 'package:dvault/src/security_box/line.dart';

import 'line_store.dart';
import 'toc_entry_builder.dart';

/// The builder allows us to create an temporary
/// TOC on disk (plain text) that doesn't have all of the
/// details that a full TOC contains.
/// The [TOCBuilder] allows us to store a list of
/// [TOCEntryBuilder]s until we are ready to create the TOC.
class TOCBuilder extends LineStore {
  TOCBuilder();

  // Adds a file to the TOC index.
  // The file is not processed in any way
  void indexFile({required String pathToFile, required String relativeTo}) {
    final tocEntry =
        TOCEntryBuilder(pathToFile: pathToFile, relativeTo: relativeTo);
    append(tocEntry);
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
        append(TOCEntryBuilder(pathToFile: path, relativeTo: relativeTo));
      }
    });
  }

  @override
  Line fromLine(String line) {
    return TOCEntryBuilder.fromLine(line);
  }
}
