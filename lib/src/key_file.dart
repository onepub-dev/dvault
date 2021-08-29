import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dcli/dcli.dart';
import 'package:dvault/src/util/exceptions.dart';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/pointycastle.dart';

import 'util/strong_key.dart';

class KeyFile {
  static const String version = '1';
  static const BEGIN_PRIVATE = '---- BEGIN DVAULT PRIVATE KEY ----';
  static const END_PRIVATE = '---- END DVAULT PRIVATE KEY ----';
  static const BEGIN_PUBLIC = '---- BEGIN DVAULT PUBLIC KEY ----';
  static const END_PUBLIC = '---- END DVAULT PUBLIC KEY ----';

  /// Path to the .dvault file which we used to store the public/private key pair.
  String get storagePath => truepath(join(HOME, '.dvault'));

  /// Saves the key pair to disk encrypting the private key.
  void save(PrivateKey privateKey, PublicKey publicKey, String passphrase) {
    storagePath.write('version:$version');
    final iv = IV.fromLength(16);
    storagePath.append('iv:${iv.base64}');

    final salt = StrongKey.generateSalt;
    final encodedSalt = base64Encode(salt);

    storagePath.append('salt:$encodedSalt');
    var encrypter = _encrypterFromPassphrase(passphrase, salt);

    // store a test message so we can easily check the passphrase
    // is correct.
    var testMessage = encrypter.encrypt('test', iv: iv);
    storagePath.append('test:${testMessage.base64}');

    storagePath.append('');
    _appendPrivateKey(privateKey, encrypter, iv);
    storagePath.append('');
    _appendPublicKey(publicKey);

    if (!Platform.isWindows) {
      /// read/write only access for user and no one else.
      chmod(600, storagePath);
    }
  }

  /// Loads the key pair from key file decrypting the private key.
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> load(String passphrase) {
    Settings().verbose('Loading Keyfile from: $storagePath');

    var lines = read(storagePath).toList();

    var version = _parseVersion(lines[0]);
    var iv = _parseIV(lines[1]);
    var salt = _parseSalt(lines[2]);
    var test = _parseTest(lines[3]);
    Settings().verbose('Storage Version: $version');

    final encrypter = _encrypterFromPassphrase(passphrase, salt);

    if (!_validatePassphrase(passphrase, encrypter, test, iv)) {
      throw InvalidPassphraseException();
    }

    var privateKey = _loadPrivateKey(lines, encrypter, iv);

    var publicKey = _loadPublicKey(lines);

    return AsymmetricKeyPair(publicKey, privateKey);
  }

  void resetPassphrase(
      {required String current, required String newPassphrase}) {
    var pair = load(current);

    save(pair.privateKey, pair.publicKey, newPassphrase);
  }

  bool _validatePassphrase(
      String passphrase, Encrypter encrypter, String base64TestMessage, IV iv) {
    var encrypted = Encrypted.fromBase64(base64TestMessage);

    var testConfirm = encrypter.decrypt(encrypted, iv: iv);

    return (testConfirm == 'test');
  }

  bool validatePassphrase(String passphrase) {
    var lines = read(storagePath).toList();
    var iv = _parseIV(lines[1]);
    var salt = _parseSalt(lines[2]);
    var base64TestMessage = _parseTest(lines[3]);

    final encrypter = _encrypterFromPassphrase(passphrase, salt);

    return _validatePassphrase(passphrase, encrypter, base64TestMessage, iv);
  }

  /// Loads just the public key from this key file.
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
  /// Append the Public Key to the key file
  ///
  void _appendPublicKey(PublicKey publicKey) {
    final rsaPublic = publicKey as RSAPublicKey;
    var modulus = rsaPublic.modulus.toString();
    var exponent = rsaPublic.exponent.toString();

    var plainTextPublicKey = '''
modulus:$modulus
exponent:$exponent''';

    storagePath.append(BEGIN_PUBLIC);
    storagePath.append(plainTextPublicKey);
    storagePath.append(END_PUBLIC);
  }

  ///
  /// Append the Private Key to the key file
  ///
  void _appendPrivateKey(PrivateKey privateKey, Encrypter encrypter, IV iv) {
    final rsaPrivate = privateKey as RSAPrivateKey;
    var modulus = rsaPrivate.modulus.toString();
    var exponent = rsaPrivate.exponent.toString();
    var p = rsaPrivate.p.toString();
    var q = rsaPrivate.q.toString();

    /// create a textual version of the private key
    var plainTextPrivateKey = '''
modulus:$modulus
exponent:$exponent
p:$p
q:$q''';

    // /// use the passphrase as the key to encrypt the private key
    // var key = Key.fromUtf8(passPhrase);
    // key = key.stretch(32);

    // final encrypter = Encrypter(AES(key));

    final encrypted = encrypter.encrypt(plainTextPrivateKey, iv: iv);

    storagePath.append(BEGIN_PRIVATE);
    storagePath.append(encrypted.base64);
    storagePath.append(END_PRIVATE);
  }

  ///
  /// Load the private key
  ///
  RSAPrivateKey _loadPrivateKey(
      List<String> lines, Encrypter encrypter, IV iv) {
    Settings().verbose('Loading PrivateKey ');

    var keyLines = _extractKey(lines, BEGIN_PRIVATE, END_PRIVATE);

    if (keyLines.length != 3) {
      throw DVaultException(
          'Invalid key file $storagePath. The Private Key should consist of 3 lines, found ${keyLines.length}. Found $keyLines\n');
    }

    var base64Encrypted = keyLines[1];
    var encrypted = Encrypted.fromBase64(base64Encrypted);
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

    var keyLines = _extractKey(lines, BEGIN_PUBLIC, END_PUBLIC);

    Settings().verbose('Read PublicKey: $keyLines');

    if (keyLines.length != 4) {
      throw DVaultException(
          'Invalid key file $storagePath. The Public Key should consist of 4 lines, found ${keyLines.length + 1}.');
    }

    var modulus = parseBigInt(keyLines[1], 'modulus', 'public');
    var exponent = parseBigInt(keyLines[2], 'exponent', 'public');
    return RSAPublicKey(modulus, exponent);
  }

  String _parseVersion(String line) {
    var parts = line.split(':');

    if (parts.length != 2) {
      throw DVaultException(
          'Invalid key file $storagePath. Version no. not found. Found $line');
    }
    return parts[1];
  }

  Encrypter _encrypterFromPassphrase(String passphrase, Uint8List salt) {
    var strongKey = StrongKey.fromPassPhrase(passphrase);

    // TODO: change interation count to 100,000 and change ui to
    // indicate the user should wait.
    // Need advice on this as using 100,000 interations takes a
    // long time. This means unlocking a file is going to take a long time.
    var key = strongKey.stretch(32, iterationCount: 1000, salt: salt);

    return Encrypter(AES(key, mode: AESMode.sic, padding: null));
  }

  /// parse big int from line.
  BigInt parseBigInt(String keyLine, String key, String keyType) {
    var parts = keyLine.trim().split(':');
    if (parts.length != 2) {
      throw DVaultException(
          '$keyType does not have a valid modulus in $storagePath');
    }

    if (parts[0] != key) {
      throw DVaultException(
          '$keyType does not have a valid modulus in $storagePath');
    }

    return BigInt.parse(parts[1]);
  }

  /// parses the key components (including the begin and end lines)
  /// out of [lines] loaded from the key file.
  List<String> _extractKey(List<String> lines, String begin, String end) {
    final keyLines = <String>[];
    var inKey = false;
    for (var line in lines) {
      line = line.trim();
      if (line.isEmpty) continue;
      if (line.startsWith(end)) {
        keyLines.add(line);
        break;
      }
      if (inKey) {
        keyLines.add(line);
      }
      if (line.startsWith(begin)) {
        keyLines.add(line);
        inKey = true;
      }
    }
    return keyLines;
  }

  /// Parse the IV from a line.
  IV _parseIV(String line) {
    var parts = line.split(':');
    if (parts.length != 2) {
      throw DVaultException(
          'Invalid key file $storagePath. IV not found. Found $line');
    }

    if (parts[0] != 'iv') {
      throw DVaultException(
          'Invalid key file $storagePath. IV not found. Found $line');
    }

    return IV.fromBase64(parts[1]);
  }

  /// Parse the base64 encoded salt from a line
  /// and return the decoded salt
  Uint8List _parseSalt(String line) {
    var parts = line.split(':');
    if (parts.length != 2) {
      throw DVaultException(
          'Invalid key file $storagePath. Salt not found. Found $line');
    }

    if (parts[0] != 'salt') {
      throw DVaultException(
          'Invalid key file $storagePath. Salt not found. Found $line');
    }

    return base64Decode(parts[1].trim());
  }

  /// Parse the base64 encoded test message from a line
  /// and return the test message still base 64 encoded.
  String _parseTest(String line) {
    var parts = line.split(':');
    if (parts.length != 2) {
      throw DVaultException(
          'Invalid key file $storagePath. Test not found. Found $line');
    }

    if (parts[0] != 'test') {
      throw DVaultException(
          'Invalid key file $storagePath. Test not found. Found $line');
    }

    return parts[1].trim();
  }
}

class DVaultException implements Exception {
  String message;
  DVaultException(this.message);
  @override
  String toString() => message;
}
