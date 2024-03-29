/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'exceptions.dart';

/// Reads a single line from [raf] and returns
/// it after removing any platform specific line
/// terminators.
/// The [description] is used only if an error message is generated
/// and is used to describe the line being read.
/// If the line contains a key:value pair then pass the key as the
/// [description].
String readLine(RandomAccessFile raf, String description) {
  final line = StringBuffer();
  var terminatorLength = 1;
  try {
    var byte = 0;

    while (byte != -1) {
      byte = raf.readByteSync();

      line.write(String.fromCharCode(byte));
      if (byte == '\r'.codeUnitAt(0)) {
        terminatorLength++;
      }
      if (byte == '\n'.codeUnitAt(0)) {
        break;
      }
    }
    if (byte == -1) {
      throw UnexpectedEndOfFileException();
    }
  } on UnexpectedEndOfFileException catch (_) {
    throw SecurityBoxReadException('Unexpected EOF reading $description');
  }

  /// we have to assume we are reading a file created on another platform
  /// that may have written different line terminators.
  return line.toString().substring(0, line.length - terminatorLength);
}

int parseNo(String line, String key) {
  final value = parseValue(line, key);
  final no = int.tryParse(value);
  if (no == null) {
    throw SecurityBoxReadException(
      'Expected integer for value in key:value pair for $key. Found $line',
    );
  }

  return no;
}

String parseValue(String keyValuePair, String key) {
  final keyPrefix = '$key:';

  final _keyValuePair = keyValuePair.trim();

  if (!_keyValuePair.startsWith(keyPrefix)) {
    throw SecurityBoxReadException(
      "Expected Key: '$key:' in key: value pair. Found $_keyValuePair",
    );
  }

  final value = _keyValuePair.substring(keyPrefix.length).trim();

  return value;
}

Future<void> withRandomAccessFile({
  required String pathTo,
  required void Function(RandomAccessFile raf) action,
  FileMode mode = FileMode.read,
}) async {
  final raf = await File(pathTo).open(mode: mode);

  action(raf);
  await raf.close();
}
