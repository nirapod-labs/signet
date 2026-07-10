// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Integration tests against the real hardware key store (device-lane; the
// analyze-only CI check confirms they compile against the plugin API). The first
// covers the non-interactive surface end to end; the second covers gated-key
// generation, which does not prompt. The interactive gated sign needs a real
// biometric and is a manual step, documented in flutter/VERIFICATION.md.

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
        await signet.generateKey(alias: alias, tierPolicy: const Strongest());
    expect(report.evidence, isNotNull);

    final publicKey = await signet.getPublicKey(handle);
    expect(publicKey.bytes, isNotEmpty);

    final digest = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final signature = await signet.sign(handle, digest);
    expect(signature, isNotEmpty);

    await signet.delete(alias);
  });

  testWidgets('generate a gated key and report its auth class',
      (WidgetTester tester) async {
    // Generating a gated key does not prompt; only signing it does. This asserts
    // the non-interactive half: the key is created with a presence check and the
    // returned report names it. Requires an enrolled biometric on the device.
    const alias = 'signet.integration.gated';
    final signet = Signet();

    await signet.delete(alias);
    final (KeyHandle handle, SecurityTierReport report) = await signet.generateKey(
      alias: alias,
      tierPolicy: const Strongest(),
      authRequirement: AuthRequirement.biometricOnly,
    );
    expect(handle.id, alias);
    expect(report.authEnforced, AuthClass.biometricOnly);

    await signet.delete(alias);
  });
}
