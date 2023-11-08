import 'package:dvault/src/security_box/toc_entry.dart';

import 'line_store.dart';

/// On disk, plain text copy of the TOC
/// containing a list of [TOCEntry]s.
/// We use this to allow for a very large TOC
/// that may not fit into memory.
class TOCStore extends LineStore {
  TOCStore();

  Stream<TOCEntry> get content => super.content as Stream<TOCEntry>;

  @override
  TOCEntry fromLine(String line) {
    return TOCEntry.fromLine(line);
  }
}
