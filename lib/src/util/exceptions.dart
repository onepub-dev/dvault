class DVaultException implements Exception {}

class InvalidPassphraseException extends DVaultException {
  @override
  String toString() => 'Invalid passphrase';
}
