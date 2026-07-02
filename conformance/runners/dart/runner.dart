// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Signet conformance runner (Dart), scaffold stub.
// Answers every behavior with "unimplemented", one answer per request.

import 'dart:convert';
import 'dart:io';

void main() {
  for (String? line = stdin.readLineSync();
      line != null;
      line = stdin.readLineSync()) {
    final text = line.trim();
    if (text.isEmpty) continue;
    final request = jsonDecode(text) as Map<String, dynamic>;
    final behavior = request['behavior'];
    if (behavior == null) continue;
    stdout.writeln(jsonEncode({'behavior': behavior, 'status': 'unimplemented'}));
  }
}
