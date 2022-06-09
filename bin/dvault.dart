#! /usr/bin/env dcli
/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */




import 'package:dvault/src/dvault.dart';

///
/// Provides a tool to take a complete backup of lastpass and store it
/// into an encrypted zip file.
///
///
void main(List<String> args) {
  runCommand(args);
}
