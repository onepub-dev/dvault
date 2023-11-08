import 'package:dcli/dcli.dart';

import 'line.dart';

/// Used by [TOCStore] and [TOCBuilder] to
/// store line based entries.
abstract class LineStore<E extends Line> {
  LineStore() : _pathToTemporaryToc = createTempFilename();

  /// path to the file containing the [TOCEntry]s.
  /// Each entry is stored as a single line.
  String _pathToTemporaryToc;

  bool _open = false;

  // return a stream of the current [TOCEntry]s.
  Stream<E> get content => read(_pathToTemporaryToc).stream.map(fromLine);

  // Adds a file to the TOC index.
  // The file is not processed in any way
  void append(Line line) {
    _openFile();
    _pathToTemporaryToc.append(line.asString);
  }

  E fromLine(String line);

  void _openFile() {
    if (!_open) {
      _open = true;
    }
  }
}
