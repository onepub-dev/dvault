import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dvault/src/lockbox/lockbox_format.dart';
import 'package:dvault/src/lockbox/lockbox_header.dart';
import 'package:dvault/src/lockbox/lockbox_page.dart';
import 'package:dvault/src/vfs/lock_box_reader.dart';
import 'package:dvault/src/vfs/lock_box_writer.dart';

class LockBoxEnvPage {
  final Map<String, String> _env;

  final LockBoxHeader _header;

  final SecretKey sessionKey;

  final int pageOffset;

  LockBoxEnvPage._(
    this._header,
    this._env,
    this.sessionKey,
    // this.writer,
  ) : pageOffset = _header.headerSize;

  LockBoxEnvPage.empty({
    required this.sessionKey,
    required LockBoxHeader header,
    // required this.writer,
  }) : _env = {},
       _header = header,
       pageOffset = header.headerSize;

  static Future<LockBoxEnvPage> read({
    required LockBoxHeader header,
    required SecretKey sessionKey,
    required LockBoxReader reader,
  }) async {
    final pageSize = header.pageSize;
    final pageOffset = header.headerSize; // Page 0 is after header
    final encryptedEnvPage = await reader.readBytesAt(pageOffset, pageSize);

    assert(encryptedEnvPage.length == pageSize);
    final envData = await LockBoxPage.decrypt(
      encryptedPage: encryptedEnvPage,
      key: sessionKey,
    );
    final env = await parseEnv(envData);

    return LockBoxEnvPage._(header, env, sessionKey); // , writer);
  }

  String? getEnv(String key) => _env[key];

  void setEnv(LockBoxWriter writer, String key, String value) async {
    _env[key] = value;
    await write(writer);
  }

  Map<String, String> listEnv() => Map.unmodifiable(_env);

  static Future<Map<String, String>> parseEnv(Uint8List data) async {
    final env = <String, String>{};
    try {
      int len = data.length;
      while (len > 0 && data[len - 1] == 0) {
        len--;
      }
      if (len == 0) return env;

      final jsonStr = String.fromCharCodes(data.sublist(0, len));
      final map = _parseJson(jsonStr) as Map;
      for (final entry in map.entries) {
        env[entry.key.toString()] = entry.value.toString();
      }
    } catch (e) {
      // Ignore parse error (empty page)
    }
    return env;
  }

  Future<void> write(LockBoxWriter writer) async {
    final jsonStr = _encodeJson(_env);
    final bytes = Uint8List.fromList(jsonStr.codeUnits);

    final payloadSize = _header.pageSize - LockBoxFormat.pageOverhead;

    if (bytes.length > payloadSize) {
      throw Exception('Environment variables too large for Page 0');
    }

    final pageData = Uint8List(payloadSize);
    pageData.setRange(0, bytes.length, bytes);

    final encryptedPage = await LockBoxPage.encrypt(
      data: pageData,
      key: sessionKey,
      pageSize: _header.pageSize,
    );

    await writer.writeBytesAt(_header.headerSize, encryptedPage);
  }

  static Map<String, dynamic> _parseJson(String json) {
    // Very basic JSON parser - in real implementation use dart:convert for CLI
    // and a web-compatible parser for browser
    final trimmed = json.trim();
    if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) {
      throw FormatException('Invalid JSON');
    }

    final content = trimmed.substring(1, trimmed.length - 1);
    final map = <String, dynamic>{};

    if (content.trim().isEmpty) return map;

    // Simple split on comma (doesn't handle nested objects)
    final pairs = content.split(',');
    for (final pair in pairs) {
      final parts = pair.split(':');
      if (parts.length != 2) continue;

      final key = parts[0].trim().replaceAll('"', '');
      final value = parts[1].trim().replaceAll('"', '');
      map[key] = value;
    }

    return map;
  }

  // Simple JSON encoding/decoding (to avoid dart:convert in web)
  static String _encodeJson(Map<String, String> map) {
    final entries = map.entries
        .map((e) => '"${_escapeJson(e.key)}":"${_escapeJson(e.value)}"')
        .join(',');
    return '{$entries}';
  }

  static String _escapeJson(String str) {
    return str
        .replaceAll('\\', '\\\\')
        .replaceAll('"', '\\"')
        .replaceAll('\n', '\\n');
  }

  // Future<Uint8List> write(LockBoxWriter writer) async {
  //   final bytes =  await LockBoxPage.encrypt(
  //     data: // Uint8List(0),
  //     key: sessionKey,
  //     pageSize: pageSize,
  //   );

  //       await writer.seek(pageOffset);
  //   await writer.write(bytes);

  //   return bytes;

  // }
}
