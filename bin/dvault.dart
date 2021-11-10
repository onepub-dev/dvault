#! /usr/bin/env dcli

import 'package:dvault/src/dvault.dart';

///
/// Provides a tool to take a complete backup of lastpass and store it
/// into an encrypted zip file.
///
///
void main(List<String> args) {
  runCommand(args);
}
