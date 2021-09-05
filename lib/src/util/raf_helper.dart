import 'dart:io';

import 'exceptions.dart';

String readLine(RandomAccessFile raf, String key) {
  var line = '';
  try {
    var byte = 0;

    while (byte != -1) {
      byte = raf.readByteSync();
      line += String.fromCharCode(byte);
      if (byte == '\n'.codeUnitAt(0)) {
        break;
      }
    }
    if (byte == -1) {
      throw UnexpectedEndOfFileException();
    }
  } on UnexpectedEndOfFileException catch (_) {
    throw VaultReadException('Unexpected EOF reading $key');
  }

  return line;
}

int parseNo(String line, String key) {
  var value = parseValue(line, key);
  var no = int.tryParse(value);
  if (no == null) {
    throw VaultReadException(
        'Expected integer for value in key:value pair for $key. Found $line');
  }

  return no;
}

String parseValue(String keyValuePair, String key) {
  var parts = keyValuePair.split(':');
  if (parts.length != 2) {
    throw VaultReadException(
        'Expected key:value pair for $key. Found $keyValuePair');
  }
  if (parts[0].trim() != key) {
    throw VaultReadException(
        'Expected Key: $key in key:value pair. Found $keyValuePair');
  }

  var value = parts[1];

  return value;
}
