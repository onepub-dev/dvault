import 'dart:io';
import 'dart:typed_data';

import 'package:dcli/dcli.dart';
import 'package:dvault/src/util/strong_key.dart';

const _delete = 127;
const _space = 32;
const _backspace = 8;

Future<StrongKey> askForPassword(String prompt) async {
  Uint8List? buffer;
  int length = 0;
  var valid = false;

  try {
    do {
      echo('$prompt ');

      final result = _readHidden();
      buffer = result.$1;
      length = result.$2;

      if (length == 0) {
        print('You must enter a passphrase');
        continue;
      }

      if (length < 12) {
        print('The pass phrase must be at least 12 characters long');
        buffer.fillRange(0, buffer.length, 0);
        continue;
      }

      verbose(() => 'ask: result length $length');
      valid = true;
    } while (!valid);

    final keyBytes = buffer.sublist(0, length);
    final strongKey = StrongKey.fromPassPhrase(keyBytes);
    return strongKey;
  } finally {
    if (buffer != null) {
      buffer.fillRange(0, buffer.length, 0);
    }
  }
}

(Uint8List, int) _readHidden() {
  final buffer = Uint8List(255);
  var index = 0;

  try {
    stdin.echoMode = false;
    stdin.lineMode = false;
    int char;
    do {
      char = stdin.readByteSync();
      if (char != 10 && char != 13) {
        if (char == _delete || char == _backspace) {
          if (index > 0) {
            // move back a character,
            // print a space and move back again.
            // required to clear the current character
            // move back one space.
            stdout
              ..writeCharCode(_backspace)
              ..writeCharCode(_space)
              ..writeCharCode(_backspace);
            index--;
            buffer[index] = 0;
          }
        } else {
          if (index < buffer.length) {
            // apparently flush isn't needed - despite the doc.
            stdout.write('*');
            buffer[index] = char;
            index++;
          }
        }
      }
    } while (char != 10 && char != 13);
  } finally {
    stdin.lineMode = true;
    stdin.echoMode = true;
  }

  // output a newline as we have suppressed it.
  print('');

  return (buffer, index);
}
