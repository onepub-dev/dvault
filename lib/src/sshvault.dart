/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:archive/archive.dart';
import 'package:dcli/dcli.dart' hide fetch;
import 'package:dcli/dcli.dart' as d;

/// Provide a simple tool which encrypts a text into  encrypted text
/// using the system ssh keys.
///
/// This tool will download and install ssh-vault into the [storagePath]
/// directory if its
/// not already installed into that dir.
///
class SSHVault {
  /// [storagePath] is the path (directory)
  /// where we are going to store the resulting vault.
  /// [privateKeyPath] the path to the private key file. If null defaults to
  /// ~/.ssh/id_rsa
  /// [publicKeyPath] the path to the private key file. If null defaults to
  /// ~/.ssh/id_rsa.pub
  SSHVault({this.storagePath, this.privateKeyPath, this.publicKeyPath}) {
    privateKeyPath ??= join(HOME, '.ssh', 'id_rsa');
    publicKeyPath ??= join(HOME, '.ssh', 'id_rsa.pub');
  }
  static const vaultExe = 'ssh-vault';
  static const version = 'ssh-vault_0.12.6_linux_amd64';

  String? storagePath;

  String? privateKeyPath;

  String? publicKeyPath;

  String get _vaultExePath => join(storagePath!, vaultExe);

  /// Stores the passed [text] into a vault located at [storagePath].
  /// If [overwrite] is true and a vault with the name [vaultName]
  /// already exist it will be overwritten.
  ///
  /// The [vaultName] must end in .vault.
  ///
  /// If [overwrite] is false and the [vaultName] file exists then
  /// a [SSHVaultException] will be thrown.
  void store({
    required String text,
    required String vaultName,
    bool overwrite = false,
  }) {
    if (!vaultName.endsWith('.vault')) {
      throw SSHVaultException(
        'Invalid vaultName. The [vaultName] must end in ".vault".',
      );
    }

    final vaultPath = join(storagePath!, vaultName);

    install();
    print('creating your vault');
    final lines = ('echo $text' |
            '$_vaultExePath -u ${Shell.current.loggedInUser} create')
        .toList();

    if (exists(vaultPath)) {
      if (!overwrite) {
        throw SSHVaultException(
          'The vault at ${truepath(vaultPath)} already exists.',
        );
      }
      delete(vaultPath);
    }

    touch(vaultPath, create: true);
    for (final line in lines) {
      vaultPath.append(line!);
    }
  }

  void storeFile({
    required String path,
    required String vaultName,
    bool overwrite = false,
  }) {
    if (!vaultName.endsWith('.vault')) {
      throw SSHVaultException(
        'Invalid vaultName. The [vaultName] must end in ".vault".',
      );
    }

    final vaultPath = join(storagePath!, vaultName);

    if (exists(vaultPath)) {
      if (!overwrite) {
        throw SSHVaultException(
          'The vault at ${truepath(vaultPath)} already exists.',
        );
      }
      delete(vaultPath);
    }

    install();
    print('creating your vault');
    ('cat $path' |
            '$_vaultExePath -u ${Shell.current.loggedInUser} create $vaultPath')
        .run;
  }

  String fetch({
    String? vaultName,
  }) {
    final vaultPath = join(storagePath!, vaultName);
    String text;

    print('fetching $vaultPath');
    if (_isPrivKeyProtected(privateKeyPath)) {
      final passphrase = ask('Private Key Passphrase:', hidden: true);
      text = ('echo $passphrase' |
              '$_vaultExePath  -k $privateKeyPath view $vaultPath ')
          .toList()
          .join('\n');
    } else {
      text = '$_vaultExePath  -k $privateKeyPath view $vaultPath'
          .toList()
          .join('\n');
    }

    return text;
  }

  void install() {
    /// already installed - no action required.
    if (exists(_vaultExePath)) {
      return;
    }

    print('Installing vault');

    const tar = 'vault.tar.gz';
    if (exists(tar)) {
      delete(tar);
    }

    print('Downloading vault.');
    d.fetch(
      url: 'https://dl.bintray.com/nbari/ssh-vault/$version.tar.gz',
      saveToPath: tar,
    );

    final bytes = File(tar).readAsBytesSync();

    print('expanding vault tar');
    final expanded = TarDecoder().decodeBytes(GZipDecoder().decodeBytes(bytes));

    final vaultArchive = expanded.findFile(join(version, vaultExe))!;
    final data = vaultArchive.content as List<int>;
    File(join(storagePath!, vaultExe))
      ..createSync(recursive: true)
      ..writeAsBytesSync(data);

    'chmod +x $_vaultExePath'.run;
  }
}

/// Check if the ssh private key file located at [path]
/// is password protected
bool _isPrivKeyProtected(String? path) {
  // run
  // ssh-keygen -y -P "" -f rsa_enc
  //
  // If we have a password
  // Load key "path_to_key": incorrect passphrase supplied to decrypt
  // private key`
  //
  // If there is no password
  // ssh-rsa AAAAB3NzaC1y...

  final line = 'ssh-keygen -y -P "" -f $path'.toList(nothrow: true).first;
  return line.startsWith('Load key');
}

class SSHVaultException implements Exception {
  SSHVaultException(this.message);
  String message;
  @override
  String toString() => message;
}

void main() {
  final vault = SSHVault(storagePath: join(HOME, 'vault'));
  const text = 'How now brown cow';
  vault.store(text: text, vaultName: 'cows', overwrite: true);

  final decrypted = vault.fetch(vaultName: 'cows');

  if (text != decrypted) {
    print('bad $text');
  } else {
    print('good');
  }
}
