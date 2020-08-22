import 'dart:io';

import 'package:dcli/dcli.dart';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/pointycastle.dart';

import 'util/strong_key.dart';

class KeyFile {
  static const String version = '1';
  static const BEGIN_PRIVATE = '---- BEGIN DVAULT PRIVATE KEY ----';
  static const END_PRIVATE = '---- END DVAULT PRIVATE KEY ----';
  static const BEGIN_PUBLIC = '---- BEGIN DVAULT PUBLIC KEY ----';
  static const END_PUBLIC = '---- END DVAULT PUBLIC KEY ----';

  String get storagePath => truepath(join(HOME, '.dvault'));

  /// Saves the key pair to disk encrypting the private key.
  void save(PrivateKey privateKey, PublicKey publicKey, String passPhrase) {
    storagePath.write('version:$version');
    final iv = IV.fromLength(16);
    storagePath.append('iv:${iv.base64}');

    _appendPrivateKey(privateKey, passPhrase, iv);
    storagePath.append('');
    _appendPublicKey(publicKey);

    if (!Platform.isWindows) {
      /// read only use and no one else.
      'chmod 600 $storagePath'.run;
    }
  }

  /// Loads the key pair from disk decrypting the private key.
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> load(String passPhrase) {
    Settings().verbose('Loading Keyfile from: $storagePath');

    var lines = read(storagePath).toList();

    var version = _parseVersion(lines[0]);
    var iv = _parseIV(lines[1]);

    Settings().verbose('Storage Version: $version');

    var privateKey = _loadPrivateKey(lines, passPhrase, iv);

    var publicKey = _loadPublicKey(lines);

    return AsymmetricKeyPair(publicKey, privateKey);
  }

  /// Loads just the public key file.
  /// Used when we are encrypting and don't need the private key.
  RSAPublicKey loadPublic() {
    Settings().verbose('Loading Keyfile from: $storagePath');

    var lines = read(storagePath).toList();

    var version = _parseVersion(lines[0]);
    Settings().verbose('Storage Version: $version');

    var publicKey = _loadPublicKey(lines);

    return publicKey;
  }

  ///
  /// Append the Public Key to the storage file
  ///
  void _appendPublicKey(PublicKey publicKey) {
    final rsaPublic = publicKey as RSAPublicKey;
    var modulus = rsaPublic.modulus.toString();
    var exponent = rsaPublic.exponent.toString();

    var plainTextPrivateKey = '''modulus:$modulus
exponent:$exponent''';

    storagePath.append(BEGIN_PUBLIC);
    storagePath.append(plainTextPrivateKey);
    storagePath.append(END_PUBLIC);
  }

  ///
  /// Append the Private Key to the storage file
  ///
  void _appendPrivateKey(PrivateKey privateKey, String passPhrase, IV iv) {
    final rsaPrivate = privateKey as RSAPrivateKey;
    var modulus = rsaPrivate.modulus.toString();
    var exponent = rsaPrivate.exponent.toString();
    var p = rsaPrivate.p.toString();
    var q = rsaPrivate.q.toString();

    var plainTextPrivateKey = '''modulus:$modulus
exponent:$exponent
p:$p
q:$q''';

    final key = Key.fromUtf8(passPhrase);
    key.stretch(128);

    final encrypter = Encrypter(AES(key));

    final encrypted = encrypter.encrypt(plainTextPrivateKey, iv: iv);

    storagePath.append(BEGIN_PRIVATE);
    storagePath.append(encrypted.base64);
    storagePath.append(END_PRIVATE);
  }

  String _parseVersion(String line) {
    var parts = line.split(':');

    if (parts.length != 2) {
      throw DVaultException('Invalid key file $storagePath. Version no. not found. Found $line');
    }
    return parts[1];
  }

  ///
  /// Load the private key
  ///
  RSAPrivateKey _loadPrivateKey(List<String> lines, String passPhrase, IV iv) {
    Settings().verbose('Loading PrivateKey ');
    final keyLines = lines
        .where((element) => element.trim().isNotEmpty) // filter empty lines.
        .skipWhile((row) => !row.startsWith(BEGIN_PRIVATE))
        .takeWhile((row) => !row.startsWith(END_PRIVATE))
        .map((row) => row.trim())
        .toList();

    if (keyLines.length != 2) {
      throw DVaultException(
          'Invalid key file $storagePath. The Private Key should consist of 3 lines, found ${keyLines.length + 1}. Found $keyLines\n');
    }

    var base64Encrypted = keyLines[1];

    var encrypted = Encrypted.fromBase64(base64Encrypted);

    final key = StrongKey.fromPassPhrase(passPhrase);
    final salt = StrongKey.generateSalt;
    key.secureStretch(salt);

    final encrypter = Encrypter(AES(key, mode: AESMode.sic));
    final decrypted = encrypter.decrypt(encrypted, iv: iv).trim().split('\n');

    if (decrypted.length != 4) {
      throw DVaultException(
          'Invalid key file $storagePath. The decrypted Private Key should consist of 4 lines, found ${keyLines.length}.');
    }

    var modulus = parseBigInt(decrypted[0], 'modulus', 'private');
    var exponent = parseBigInt(decrypted[1], 'exponent', 'private');
    var p = parseBigInt(decrypted[2], 'p', 'private');
    var q = parseBigInt(decrypted[3], 'q', 'private');

    return RSAPrivateKey(modulus, exponent, p, q);
  }

  ///
  /// Load the public key
  ///
  RSAPublicKey _loadPublicKey(List<String> lines) {
    Settings().verbose('Loading PublicKey ');
    final keyLines = lines
        .where((element) => element.trim().isNotEmpty) // filter empty lines.
        .skipWhile((row) => !row.startsWith(BEGIN_PUBLIC))
        .takeWhile((row) => !row.startsWith(END_PUBLIC))
        .map((row) => row.trim())
        .toList();

    Settings().verbose('Read PublicKey: $keyLines');

    if (keyLines.length != 3) {
      throw DVaultException(
          'Invalid key file $storagePath. The Public Key should consist of 4 lines, found ${keyLines.length + 1}.');
    }

    var modulus = parseBigInt(keyLines[1], 'modulus', 'public');
    var exponent = parseBigInt(keyLines[2], 'exponent', 'public');
    return RSAPublicKey(modulus, exponent);
  }

  /// parse big int from line.
  BigInt parseBigInt(String keyLine, String key, String keyType) {
    var parts = keyLine.trim().split(':');
    if (parts.length != 2) {
      throw DVaultException('$keyType does not have a valid modulus in $storagePath');
    }

    if (parts[0] != key) {
      throw DVaultException('$keyType does not have a valid modulus in $storagePath');
    }

    return BigInt.parse(parts[1]);
  }

  /// Parse the IV from a line.
  IV _parseIV(String line) {
    var parts = line.split(':');
    if (parts.length != 2) {
      throw DVaultException('Invalid key file $storagePath. IV not found. Found $line');
    }

    if (parts[0] != 'iv') {
      throw DVaultException('Invalid key file $storagePath. IV not found. Found $line');
    }

    return IV.fromBase64(parts[1]);
  }
}

class DVaultException implements Exception {
  String message;
  DVaultException(this.message);
  @override
  String toString() => message;
}
