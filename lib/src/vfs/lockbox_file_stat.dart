import 'dart:io';

class LockBoxFileStat implements FileStat {
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

  LockBoxFileStat({
    required this.changed,
    required this.modified,
    required this.accessed,
    required this.type,
    required this.mode,
    required this.size,
  });

  static LockBoxFileStat notFound() {
    return LockBoxFileStat(
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
