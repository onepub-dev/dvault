import 'package:dcli/dcli.dart';
import 'package:dvault/src/util/exceptions.dart';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/pointycastle.dart';

/// Converts RSA Keys between Dart Objects and Strings
/// suitable for storage.

class RSAConvertor {
  static const BEGIN_PRIVATE = '---- BEGIN DVAULT PRIVATE KEY ----';
  static const END_PRIVATE = '---- END DVAULT PRIVATE KEY ----';
  static const BEGIN_PUBLIC = '---- BEGIN DVAULT PUBLIC KEY ----';
  static const END_PUBLIC = '---- END DVAULT PUBLIC KEY ----';

  static int get privateKeyLines => 3;
  static int get publicKeyLines => 4;

  ///
  /// Returns a text representation of the
  /// Public Key to suitable for storing
  /// the key and later loading it.
  ///
  /// The PublicKey is stored as plain text
  /// as there is no reason to encrypt a
  /// public key.
  ///
  static String publicKeyAsText(RSAPublicKey publicKey) {
    var modulus = publicKey.modulus.toString();
    var exponent = publicKey.exponent.toString();

    var text = '''
$BEGIN_PUBLIC
modulus:$modulus
exponent:$exponent
$END_PUBLIC''';
    return text;
  }

  /// Returns a text representation of the [privateKey]
  /// suitable for storing the key and later reloading it.
  ///
  /// The [privateKey] is encrypted using the [encrpter]
  /// to key it from prying eyes.
  ///
  static String privateKeyAsText(
      RSAPrivateKey privateKey, Encrypter encrypter, IV iv) {
    var modulus = privateKey.modulus.toString();
    var exponent = privateKey.exponent.toString();
    var p = privateKey.p.toString();
    var q = privateKey.q.toString();

    /// create a textual version of the private key
    var parts = '''
modulus:$modulus
exponent:$exponent
p:$p
q:$q''';

    // /// use the passphrase as the key to encrypt the private key
    // var key = Key.fromUtf8(passPhrase);
    // key = key.stretch(32);

    // final encrypter = Encrypter(AES(key));
    final encrypted = encrypter.encrypt(parts, iv: iv);

    return '''
    $BEGIN_PRIVATE);
    ${encrypted.base64};
    $END_PRIVATE''';
  }

  ///
  /// Loads a private key from the passed [lines]
  /// which may contain other data (that will be ignored).
  ///
  /// The text representaton of the key must have been
  /// created via the [privateKeyAsText] method.
  ///
  static RSAPrivateKey extractPrivateKey(
      List<String> lines, Encrypter encrypter, IV iv) {
    Settings().verbose('Loading PrivateKey ');

    var keyLines = _extractKey(lines, BEGIN_PRIVATE, END_PRIVATE);

    if (keyLines.length != privateKeyLines) {
      throw KeyException(
          'The Private Key should consist of 3 lines, found ${keyLines.length}. Found $keyLines\n');
    }

    var base64Encrypted = keyLines[1];
    var encrypted = Encrypted.fromBase64(base64Encrypted);
    final decrypted = encrypter.decrypt(encrypted, iv: iv).trim().split('\n');

    if (decrypted.length != 4) {
      throw KeyException(
          'The decrypted Private Key should consist of 4 lines, found ${keyLines.length}.');
    }

    var modulus = parseBigInt(decrypted[0], 'modulus', 'private');
    var exponent = parseBigInt(decrypted[1], 'exponent', 'private');
    var p = parseBigInt(decrypted[2], 'p', 'private');
    var q = parseBigInt(decrypted[3], 'q', 'private');

    return RSAPrivateKey(modulus, exponent, p, q);
  }

  static List<String> extractPrivateKeyLines(List<String> lines) {
    var keyLines = _extractKey(lines, BEGIN_PRIVATE, END_PRIVATE);

    if (keyLines.length != privateKeyLines) {
      throw KeyException(
          'The Private Key should consist of 3 lines, found ${keyLines.length}. Found $keyLines\n');
    }
    return keyLines;
  }

  ///
  /// Extracts a text encoded public key
  /// for a set of lines that may contain other
  /// data which which will be ignored.
  ///
  /// The key should have been encoded by the
  /// [publicKeyAsText] method.
  ///
  static RSAPublicKey extractPublicKey(List<String> lines) {
    Settings().verbose('Loading PublicKey ');

    var keyLines = extractPublicKeyLines(lines);
    Settings().verbose('Read PublicKey: $keyLines');

    var modulus = parseBigInt(keyLines[1], 'modulus', 'public');
    var exponent = parseBigInt(keyLines[2], 'exponent', 'public');
    return RSAPublicKey(modulus, exponent);
  }

  static List<String> extractPublicKeyLines(List<String> lines) {
    Settings().verbose('Loading PublicKey ');

    var keyLines = _extractKey(lines, BEGIN_PUBLIC, END_PUBLIC);

    if (keyLines.length != publicKeyLines) {
      throw KeyException(
          'The Public Key should consist of 4 lines, found ${keyLines.length + 1}.');
    }

    return keyLines;
  }

  /// parse big int from line.
  static BigInt parseBigInt(String keyLine, String key, String keyType) {
    var parts = keyLine.trim().split(':');
    if (parts.length != 2) {
      throw KeyException('$keyType does not have a valid modulus.');
    }

    if (parts[0] != key) {
      throw KeyException('$keyType does not have a valid modulus.');
    }

    return BigInt.parse(parts[1]);
  }

  /// parses the key components (including the begin and end lines)
  /// out of [lines] loaded from the key file.
  static List<String> _extractKey(
      List<String> lines, String begin, String end) {
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
}
