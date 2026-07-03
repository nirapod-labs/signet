// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:signet/signet.dart';

void main() => runApp(const SignetExampleApp());

class SignetExampleApp extends StatelessWidget {
  const SignetExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Signet',
      theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  static const String _alias = 'signet.example.demo';
  static const String _gatedAlias = 'signet.example.gated';

  final Signet _signet = Signet();
  String _status = 'Generate a hardware key and sign a digest.';
  bool _busy = false;

  Future<void> _run() async {
    setState(() => _busy = true);
    try {
      // Best effort so the demo also runs on a device or emulator without a
      // discrete secure element; the report states what was actually achieved.
      await _signet.delete(_alias);
      final (KeyHandle handle, SecurityTierReport report) =
          await _signet.generateKey(alias: _alias, tierPolicy: const BestEffort());
      final publicKey = await _signet.getPublicKey(handle);
      final digest = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final signature = await _signet.sign(handle, digest);
      setState(() {
        _status = 'tier: ${report.achieved.name} '
            '(evidence: ${report.evidence.name})\n'
            'public key: ${publicKey.bytes.length} bytes\n'
            'signature: ${signature.length} bytes';
      });
    } on SignetException catch (error) {
      setState(() => _status = 'SignetException: ${error.code.name}');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _runGated() async {
    setState(() => _busy = true);
    try {
      // A gated key: signing it requires a biometric or the device credential.
      // The native side presents the prompt and authenticates the key; this code
      // never sees the credential. A cancel surfaces as SignetErrorCode.userCanceled.
      await _signet.delete(_gatedAlias);
      final (KeyHandle handle, _) = await _signet.generateKey(
        alias: _gatedAlias,
        tierPolicy: const BestEffort(),
        authRequirement: AuthRequirement.biometricOrDeviceCredential,
      );
      final digest = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final signature = await _signet.sign(
        handle,
        digest,
        prompt: const AuthPrompt(
          title: 'Approve signature',
          subtitle: 'Authenticate to sign the demo digest',
          authRequirement: AuthRequirement.biometricOrDeviceCredential,
        ),
      );
      setState(() => _status = 'gated signature: ${signature.length} bytes');
    } on SignetException catch (error) {
      setState(() => _status = 'SignetException: ${error.code.name}');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Signet example')),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Padding(
              padding: const EdgeInsets.all(24),
              child: Text(_status, textAlign: TextAlign.center),
            ),
            FilledButton(
              onPressed: _busy ? null : _run,
              child: const Text('Generate key and sign'),
            ),
            const SizedBox(height: 12),
            OutlinedButton(
              onPressed: _busy ? null : _runGated,
              child: const Text('Generate gated key and sign'),
            ),
          ],
        ),
      ),
    );
  }
}
