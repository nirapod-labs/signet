// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Integration test for the non-interactive surface. It runs in a full Flutter
// app, so it reaches the native core and the real hardware key store, unlike the
// Dart unit tests. It is exercised on the device lane; the analyze-only CI checks
// that it compiles against the plugin API.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:signet/signet.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('generate a key, read its public key, and sign a digest',
      (WidgetTester tester) async {
    const alias = 'signet.integration.demo';
    final signet = Signet();

    await signet.delete(alias);
    final (KeyHandle handle, SecurityTierReport report) =
        await signet.generateKey(alias: alias, tierPolicy: const BestEffort());
    expect(report.evidence, isNotNull);

    final publicKey = await signet.getPublicKey(handle);
    expect(publicKey.bytes, isNotEmpty);

    final digest = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final signature = await signet.sign(handle, digest);
    expect(signature, isNotEmpty);

    await signet.delete(alias);
  });
}
