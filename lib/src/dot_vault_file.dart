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

  var _lines = <String>[];

  RSAPrivateKey? _privateKey;
  RSAPublicKey? _publicKey;

  late final IV iv;
  late final Uint8List salt;
  late final String _test;

  /// Saves the key pair to disk encrypting the private key.
  static void create(
    RSAPrivateKey privateKey,
    RSAPublicKey publicKey,
    String passphrase,
  ) {
    storagePath.write('version:$version');
    final _iv = IV.fromSecureRandom(16);
    storagePath.append('iv:${_iv.base64}');

    final salt = StrongKey.generateSalt;

    storagePath.append('salt:${base64Encode(salt)}');
    final encrypter = _encrypterFromPassphrase(passphrase, salt);

    // store a test message so we can easily check the passphrase
    // is correct.
    final test = encrypter.encrypt('test', iv: _iv).base64;
    storagePath.append('test:$test');

    storagePath.append('');
    _appendPrivateKey(privateKey, encrypter, _iv);
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

    _lines = read(storagePath).toList();

    final version = _parseVersion(_lines[0]);
    iv = _parseIV(_lines[1]);
    salt = _parseSalt(_lines[2]);
    _test = _parseTest(_lines[3]);
    Settings().verbose('Storage Version: $version');
  }

  RSAPrivateKey privateKey({required String passphrase}) {
    if (_privateKey == null) {
      final encrypter = _encrypterFromPassphrase(passphrase, salt);

      if (!_validatePassphrase(passphrase, encrypter)) {
        throw InvalidPassphraseException();
      }

      _privateKey = RSAConvertor.extractPrivateKey(_lines, encrypter, iv);
    }
    return _privateKey!;
  }

  /// Returns an ecrypted version of the private key
  /// stored in the .dvault file.
  String privateKeyAsText(String passphrase) {
    return RSAConvertor.privateKeyAsText(
      privateKey(passphrase: passphrase),
      encryptor(passphrase),
      iv,
    );
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
    _publicKey ??= _loadPublicKey(_lines);
    return _publicKey!;
  }

  void resetPassphrase({
    required String current,
    required String newPassphrase,
  }) {
    backupFile(DotVaultFile.storagePath);
    delete(DotVaultFile.storagePath);
    DotVaultFile.create(
      privateKey(passphrase: current),
      publicKey,
      newPassphrase,
    );
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
    final encrypted = Encrypted.fromBase64(_test);

    String testConfirm;
    try {
      testConfirm = encrypter.decrypt(encrypted, iv: iv);
      // ignore: avoid_catching_errors
    } on ArgumentError catch (_) {
      // a pad block error is what we get if the
      // password doesn't match.
      return false;
    }
    return testConfirm == 'test';
  }

  bool validatePassphrase(String passphrase) {
    final encrypter = _encrypterFromPassphrase(passphrase, salt);

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
    RSAPrivateKey privateKey,
    Encrypter encrypter,
    IV _iv,
  ) {
    storagePath
        .append(RSAConvertor.privateKeyAsText(privateKey, encrypter, _iv));
  }

  /// Creates an AES [Encryptor] from the given [passphrase]
  /// and the salt held in the .vault file.
  Encrypter encryptor(String passphrase) {
    return _encrypterFromPassphrase(passphrase, salt);
  }

  /// Creates an AES encryptor from [passphrase]
  /// We use this encryptor for encrypting/decrypting the text
  /// representation of the PrivateKey.
  static Encrypter _encrypterFromPassphrase(String passphrase, Uint8List salt) {
    final strongKey = StrongKey.fromPassPhrase(passphrase);

    // TODO: change interation count to 100,000 and change ui to
    // indicate the user should wait.
    // Need advice on this as using 100,000 interations takes a
    // long time. This means unlocking a file is going to take a long time.
    final key = strongKey.stretch(32, iterationCount: 1000, salt: salt);
    // padding was null but I think we resolved the issue.
    return Encrypter(AES(key));
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
    return RSAConvertor.extractPrivateKeyLines(_lines);
  }

  /// Extract the Private Key from the .vault file
  /// The key is extracted verbatium and as such is
  /// still encrypted.
  List<String> extractPublicKeyLines() {
    return RSAConvertor.extractPublicKeyLines(_lines);
  }

  String _parseVersion(String line) {
    final parts = line.split(':');

    if (parts.length != 2) {
      throw DotVaultException('Version no. not found. Found $line');
    }
    return parts[1];
  }

  /// Parse the IV from a line.
  static IV _parseIV(String line) {
    final parts = line.split(':');
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
    final parts = line.split(':');
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
    final parts = line.split(':');
    if (parts.length != 2) {
      throw KeyException('Test not found. Found $line');
    }

    if (parts[0] != 'test') {
      throw KeyException('Test not found. Found $line');
    }

    return parts[1].trim();
  }
}


