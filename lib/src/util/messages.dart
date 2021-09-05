import 'package:dcli/dcli.dart';

void printBackupMessage(String pathToDotVault) {
  print('');
  print(orange('*' * 80));
  print(orange('*'));
  print(orange(
      '* If you lose your passphrase you will irretrievably lose access to all files protected with DVault'));
  print(orange('*'));
  print(
      orange('* You should now backup your .dvault file for the same reason.'));
  print(
      orange('* Your .dvault file is located at ${truepath(pathToDotVault)}'));
  print(orange('*'));
  print(orange('*' * 80));
}
