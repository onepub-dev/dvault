/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */


// ignore: unused_import
import 'package:encrypt/encrypt.dart';

class DVaultException implements Exception {
  String message;

  DVaultException(this.message);

  @override
  String toString() => message;
}

class InvalidPassphraseException extends DVaultException {
  InvalidPassphraseException() : super('Invalid passphrase');
}

class VaultWriteException extends DVaultException {
  Exception e;

  VaultWriteException(this.e)
      : super('An error occured adding a file to a vault: ${e.toString()}');
}

class VaultReadException extends DVaultException {
  VaultReadException(String message) : super(message);
}

class UnexpectedEndOfFileException extends DVaultException {
  UnexpectedEndOfFileException() : super('Unexpected end of file.');
}

class KeyException extends DVaultException {
  KeyException(String message) : super(message);
}

/// Thrown when an error is found in the ~/.dvault
/// settings file.
class DotVaultException extends DVaultException {
  DotVaultException(String message) : super(message);
}
