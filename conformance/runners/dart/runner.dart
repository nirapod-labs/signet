// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Signet conformance runner (Dart).
//
// A stub that answers every behavior "unimplemented", one answer per request
// (no silent skip). The Dart binding is a thin channel over the native cores and
// imports Flutter, so it cannot run as a standalone `dart` process against real
// hardware: its behavioral conformance runs on a device through
// flutter/SignetApp's integration_test, and its cryptographic outputs are
// inherited from the apple/ and android/ cores the conformance suite already
// exercises. See flutter/VERIFICATION.md.

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
