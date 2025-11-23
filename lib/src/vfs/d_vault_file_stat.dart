import 'dart:io';

class DVaultFileStat implements FileStat {
  @override
  final DateTime changed;
  @override
  final DateTime modified;
  @override
  final DateTime accessed;
  @override
  final FileSystemEntityType type;
  @override
  final int mode;
  @override
  final int size;

  DVaultFileStat({
    required this.changed,
    required this.modified,
    required this.accessed,
    required this.type,
    required this.mode,
    required this.size,
  });

  static DVaultFileStat notFound() {
    return DVaultFileStat(
      changed: DateTime.now(),
      modified: DateTime.now(),
      accessed: DateTime.now(),
      type: FileSystemEntityType.notFound,
      mode: 0,
      size: 0,
    );
  }

  @override
  String modeString() => 'rwxrwxrwx';
}
