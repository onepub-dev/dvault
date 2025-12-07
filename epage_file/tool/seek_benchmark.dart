import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:epage_file/epage_file.dart';

/// Simple seek/read benchmark for a large EPageFile (default 1GB).
///
/// Usage:
///   dart run tool/seek_benchmark.dart [--path /tmp/epage_bench.epage]
///       [--size-mb 1024] [--iterations 500] [--read-size 4096] [--reuse]
///
/// The benchmark writes the file once (unless --reuse is supplied),
/// then performs random seek + small read operations and reports the
/// aggregate and per-operation timings.
Future<void> main(List<String> args) async {
  final config = _BenchmarkConfig.fromArgs(args);

  final targetFile = File(config.path);
  targetFile.parent.createSync(recursive: true);

  if (targetFile.existsSync() && !config.reuseExisting) {
    targetFile.deleteSync();
  }

  final key = SecretKey(List.filled(32, 1));
  final store = await FileBackingStore.open(config.path);
  final file = await EPageFile.open(store, key: key, cacheSize: 32);

  final sizeBytes = config.sizeMb * 1024 * 1024;
  final logicalLength = await file.length();

  if (!config.reuseExisting || logicalLength < sizeBytes) {
    stdout.writeln(
      'Populating ${config.sizeMb}MB file at ${config.path} '
      '(chunkSize=${config.chunkSize ~/ (1024 * 1024)}MB)...',
    );
    final chunk = Uint8List(config.chunkSize);
    for (var i = 0; i < chunk.length; i++) {
      chunk[i] = i % 256;
    }

    var written = 0;
    final writeSw = Stopwatch()..start();
    while (written < sizeBytes) {
      final remaining = sizeBytes - written;
      final bytesThisWrite = remaining < chunk.length
          ? remaining
          : chunk.length;
      final slice = bytesThisWrite == chunk.length
          ? chunk
          : Uint8List.sublistView(chunk, 0, bytesThisWrite);
      await file.writeAt(written, slice);
      written += bytesThisWrite;
    }
    await file.flush();
    writeSw.stop();

    final seconds = writeSw.elapsed.inMilliseconds / 1000;
    final throughputMb = seconds == 0 ? 0 : (config.sizeMb / seconds);
    stdout.writeln(
      'Populate completed in ${writeSw.elapsed} '
      '(${throughputMb.toStringAsFixed(1)} MB/s).',
    );
  } else {
    stdout.writeln(
      'Reusing existing file at ${config.path} '
      '(${logicalLength ~/ (1024 * 1024)}MB logical length).',
    );
  }

  // Seek + small read benchmark
  final offsets = _buildOffsets(config.iterations, sizeBytes, config.readSize);
  final seekSw = Stopwatch()..start();
  for (final offset in offsets) {
    await file.readAt(offset, config.readSize);
  }
  seekSw.stop();

  final averageUs = seekSw.elapsedMicroseconds / config.iterations;
  stdout.writeln(
    'Seek+read ${config.readSize}B x ${config.iterations} '
    '=> total ${seekSw.elapsed}, avg ${averageUs.toStringAsFixed(1)}µs/op',
  );

  await file.close();
}

List<int> _buildOffsets(int count, int upperExclusive, int readSize) {
  final random = Random(42);
  final maxOffset = upperExclusive - readSize;
  return List<int>.generate(
    count,
    (_) => maxOffset > 0 ? random.nextInt(maxOffset) : 0,
  );
}

class _BenchmarkConfig {
  final String path;
  final int sizeMb;
  final int iterations;
  final int readSize;
  final bool reuseExisting;
  final int chunkSize;

  _BenchmarkConfig({
    required this.path,
    required this.sizeMb,
    required this.iterations,
    required this.readSize,
    required this.reuseExisting,
    required this.chunkSize,
  });

  factory _BenchmarkConfig.fromArgs(List<String> args) {
    var path = '${Directory.systemTemp.path}/epage_file/seek_benchmark.epage';
    var sizeMb = 1024;
    var iterations = 500;
    var readSize = 4096;
    var reuseExisting = false;
    var chunkSize = 4 * 1024 * 1024; // 4MB

    void requireValue(int index) {
      if (index >= args.length) {
        _usage('Missing value for ${args[index - 1]}');
      }
    }

    for (var i = 0; i < args.length; i++) {
      switch (args[i]) {
        case '--path':
          requireValue(i + 1);
          path = args[++i];
          break;
        case '--size-mb':
          requireValue(i + 1);
          sizeMb = int.parse(args[++i]);
          break;
        case '--iterations':
          requireValue(i + 1);
          iterations = int.parse(args[++i]);
          break;
        case '--read-size':
          requireValue(i + 1);
          readSize = int.parse(args[++i]);
          break;
        case '--chunk-size':
          requireValue(i + 1);
          chunkSize = int.parse(args[++i]);
          break;
        case '--reuse':
          reuseExisting = true;
          break;
        case '--help':
        case '-h':
          _usage();
        default:
          _usage('Unknown argument: ${args[i]}');
      }
    }

    if (sizeMb <= 0) {
      _usage('--size-mb must be positive');
    }
    if (iterations <= 0) {
      _usage('--iterations must be positive');
    }
    if (readSize <= 0) {
      _usage('--read-size must be positive');
    }
    if (chunkSize <= 0) {
      _usage('--chunk-size must be positive');
    }

    return _BenchmarkConfig(
      path: path,
      sizeMb: sizeMb,
      iterations: iterations,
      readSize: readSize,
      reuseExisting: reuseExisting,
      chunkSize: chunkSize,
    );
  }

  static Never _usage([String? error]) {
    if (error != null) {
      stderr.writeln(error);
    }
    stderr.writeln('''
Seek benchmark for Encrypted Page File.

Options:
  --path <path>        Location for the benchmark file
  --size-mb <int>      Logical file size in MB (default: 1024)
  --iterations <int>   Number of seek+read iterations (default: 500)
  --read-size <int>    Bytes to read after each seek (default: 4096)
  --chunk-size <int>   Chunk size used when creating the file in bytes (default: 4194304)
  --reuse              Reuse the existing file instead of recreating
  -h, --help           Show this help
''');
    exit(64);
  }
}
