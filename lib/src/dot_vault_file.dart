import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dcli/dcli.dart';
import 'package:dvault/src/rsa/convertor.dart';
import 'package:dvault/src/util/exceptions.dart';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/pointycastle.dart';

import 'util/strong_key.dart';

/// DVault stores its configuration in a text file
/// stored at ~/.dvault
/// The .dvault file includes the default public
/// and private key files.
/// The private key is encrypted using the user's
/// passphrase.
///
/// You can safely copy the .dvault file from
/// system to system.
class DotVaultFile {
  static const String version = '1';

  /// Path to the .dvault file which we used to store the public/private key pair.
  static late final String storagePath = truepath(join(HOME, '.dvault'));

  var lines = <String>[];

  RSAPrivateKey? _privateKey;
  RSAPublicKey? _publicKey;

  var _iv;
  var _salt;
  var _test;

  /// Saves the key pair to disk encrypting the private key.
  static void create(
      RSAPrivateKey privateKey, RSAPublicKey publicKey, String passphrase) {
    storagePath.write('version:$version');
    var iv = IV.fromLength(16);
    storagePath.append('iv:${iv.base64}');

    final salt = StrongKey.generateSalt;

    storagePath.append('salt:${base64Encode(salt)}');
    var encrypter = _encrypterFromPassphrase(passphrase, salt);

    // store a test message so we can easily check the passphrase
    // is correct.
    final test = encrypter.encrypt('test', iv: iv).base64;
    storagePath.append('test:$test');

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
  DotVaultFile.load() {
    Settings().verbose('Loading Keyfile from: $storagePath');

    lines = read(storagePath).toList();

    var version = _parseVersion(lines[0]);
    _iv = _parseIV(lines[1]);
    _salt = _parseSalt(lines[2]);
    _test = _parseTest(lines[3]);
    Settings().verbose('Storage Version: $version');
  }

  RSAPrivateKey privateKey({required String passphrase}) {
    if (_privateKey == null) {
      final encrypter = _encrypterFromPassphrase(passphrase, _salt);

      if (!_validatePassphrase(passphrase, encrypter)) {
        throw InvalidPassphraseException();
      }

      _privateKey = RSAConvertor.extractPrivateKey(lines, encrypter, _iv);
    }
    return _privateKey!;
  }

  /// Returns an ecrypted version of the private key
  /// stored in the .dvault file.
  String privateKeyAsText(String passphrase) {
    return RSAConvertor.privateKeyAsText(
        privateKey(passphrase: passphrase), encryptor(passphrase), _iv);
  }

  /// Returns the public key stored in the .dvault file
  /// in a text representation suitable for storage
  /// and later retrival.
  String publicKeyAsText() {
    return RSAConvertor.publicKeyAsText(publicKey);
  }

  /// Loads just the public key from this key file.
  /// Used when we are encrypting and don't need the private key.
  RSAPublicKey get publicKey {
    _publicKey ??= _loadPublicKey(lines);
    return _publicKey!;
  }

  void resetPassphrase(
      {required String current, required String newPassphrase}) {
    backupFile(DotVaultFile.storagePath);
    delete(DotVaultFile.storagePath);
    DotVaultFile.create(
        privateKey(passphrase: current), publicKey, newPassphrase);
  }

  // /// Encryptes the passed text using
  // Encrypted encrypt({required String text, required String passphrase}) {
  //   var encrypter = _encrypterFromPassphrase(passphrase, _salt);
  //   return encrypter.encrypt(text, iv: _iv);
  // }

  // String decrypt({required Encrypted encrypted, required String passphrase}) {
  //   var encrypter = _encrypterFromPassphrase(passphrase, _salt);
  // }

  bool _validatePassphrase(String passphrase, Encrypter encrypter) {
    var encrypted = Encrypted.fromBase64(_test);

    var testConfirm = encrypter.decrypt(encrypted, iv: _iv);

    return (testConfirm == 'test');
  }

  bool validatePassphrase(String passphrase) {
    final encrypter = _encrypterFromPassphrase(passphrase, _salt);

    return _validatePassphrase(passphrase, encrypter);
  }

  ///
  /// Append the Public Key to the key file
  ///
  static void _appendPublicKey(PublicKey publicKey) {
    final rsaPublic = publicKey as RSAPublicKey;
    storagePath.append(RSAConvertor.publicKeyAsText(rsaPublic));
  }

  ///
  /// Append the Private Key to the key file
  ///
  static void _appendPrivateKey(
      RSAPrivateKey privateKey, Encrypter encrypter, IV iv) {
    storagePath
        .append(RSAConvertor.privateKeyAsText(privateKey, encrypter, iv));
  }

  /// Creates an AES [Encryptor] from the given [passphrase]
  /// and the salt held in the .vault file.
  Encrypter encryptor(String passphrase) {
    return _encrypterFromPassphrase(passphrase, _salt);
  }

  /// Creates an AES encryptor from [passphrase]
  /// We use this encryptor for encrypting/decrypting the text
  /// representation of the PrivateKey.
  static Encrypter _encrypterFromPassphrase(String passphrase, Uint8List salt) {
    var strongKey = StrongKey.fromPassPhrase(passphrase);

    // TODO: change interation count to 100,000 and change ui to
    // indicate the user should wait.
    // Need advice on this as using 100,000 interations takes a
    // long time. This means unlocking a file is going to take a long time.
    var key = strongKey.stretch(32, iterationCount: 1000, salt: salt);

    return Encrypter(AES(key, mode: AESMode.sic, padding: null));
  }

  RSAPublicKey _loadPublicKey(List<String> lines) {
    try {
      return RSAConvertor.extractPublicKey(lines);
    } on KeyException catch (e) {
      throw DotVaultException('Invalid key file $storagePath. ${e.message}');
    }
  }

  /// Extract the Private Key from the .vault file
  /// The key is extracted verbatium and as such is
  /// still encrypted.
  List<String> extractPrivateKeyLines() {
    return RSAConvertor.extractPrivateKeyLines(lines);
  }

  /// Extract the Private Key from the .vault file
  /// The key is extracted verbatium and as such is
  /// still encrypted.
  List<String> extractPublicKeyLines() {
    return RSAConvertor.extractPublicKeyLines(lines);
  }

  String _parseVersion(String line) {
    var parts = line.split(':');

    if (parts.length != 2) {
      throw DotVaultException('Version no. not found. Found $line');
    }
    return parts[1];
  }

  /// Parse the IV from a line.
  static IV _parseIV(String line) {
    var parts = line.split(':');
    if (parts.length != 2) {
      throw DotVaultException('IV not found. Found $line');
    }

    if (parts[0] != 'iv') {
      throw DotVaultException('IV not found. Found $line');
    }

    return IV.fromBase64(parts[1]);
  }

  /// Parse the base64 encoded salt from a line
  /// and return the decoded salt
  Uint8List _parseSalt(String line) {
    var parts = line.split(':');
    if (parts.length != 2) {
      throw KeyException('Salt not found. Found $line');
    }

    if (parts[0] != 'salt') {
      throw KeyException('Salt not found. Found $line');
    }

    return base64Decode(parts[1].trim());
  }

  /// Parse the base64 encoded test message from a line
  /// and return the test message still base 64 encoded.
  String _parseTest(String line) {
    var parts = line.split(':');
    if (parts.length != 2) {
      throw KeyException('Test not found. Found $line');
    }

    if (parts[0] != 'test') {
      throw KeyException('Test not found. Found $line');
    }

    return parts[1].trim();
  }
}
