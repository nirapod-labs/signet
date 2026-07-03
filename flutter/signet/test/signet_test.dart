// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:signet/signet.dart';
import 'package:signet/src/messages.g.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _FakeHost host;
  late Signet signet;

  setUp(() {
    host = _FakeHost();
    signet = Signet.withHostApi(host);
  });

  group('generateKey', () {
    test('marshals Strongest and rebuilds the handle and report', () async {
      host.generateResult = GenerateResultWire(
        handleId: 'wallet',
        report: _report(SecurityLevelWire.secureEnclave),
      );

      final (handle, report) = await signet.generateKey(alias: 'wallet');

      expect(handle.id, 'wallet');
      expect(host.lastGenerateSpec!.alias, 'wallet');
      expect(host.lastGenerateSpec!.tierPolicyKind, TierPolicyKindWire.strongest);
      expect(host.lastGenerateSpec!.atLeastClass, isNull);
      expect(report.achieved, SecurityLevel.secureEnclave);
      expect(report.evidence, TierEvidence.seTokenPresent);
      expect(report.meetsFloor, isTrue);
      expect(report.requested, isNull);
      expect(report.authEnforced, isNull);
    });

    test('AtLeast carries its class across the wire', () async {
      host.generateResult = GenerateResultWire(
        handleId: 'k',
        report: _report(SecurityLevelWire.strongBox),
      );

      await signet.generateKey(
        alias: 'k',
        tierPolicy: const AtLeast(HardwareClass.discreteSecure),
      );

      expect(host.lastGenerateSpec!.tierPolicyKind, TierPolicyKindWire.atLeast);
      expect(host.lastGenerateSpec!.atLeastClass, HardwareClassWire.discreteSecure);
    });

    test('BestEffort maps to its kind with no class', () async {
      host.generateResult = GenerateResultWire(
        handleId: 'k',
        report: _report(SecurityLevelWire.software),
      );

      await signet.generateKey(alias: 'k', tierPolicy: const BestEffort());

      expect(host.lastGenerateSpec!.tierPolicyKind, TierPolicyKindWire.bestEffort);
      expect(host.lastGenerateSpec!.atLeastClass, isNull);
    });

    test('forwards the attestation challenge', () async {
      host.generateResult = GenerateResultWire(
        handleId: 'k',
        report: _report(SecurityLevelWire.strongBox),
      );
      final challenge = Uint8List.fromList([1, 2, 3]);

      await signet.generateKey(alias: 'k', attestationChallenge: challenge);

      expect(host.lastGenerateSpec!.attestationChallenge, challenge);
    });

    test('marshals the access-control request', () async {
      host.generateResult = GenerateResultWire(
        handleId: 'gated',
        report: _report(SecurityLevelWire.secureEnclave),
      );

      await signet.generateKey(
        alias: 'gated',
        authRequirement: AuthRequirement.biometricOrDeviceCredential,
        authValiditySeconds: 30,
        invalidateOnBiometricEnrollment: false,
      );

      expect(host.lastGenerateSpec!.authRequirement,
          AuthRequirementWire.biometricOrDeviceCredential);
      expect(host.lastGenerateSpec!.authValiditySeconds, 30);
      expect(host.lastGenerateSpec!.invalidateOnBiometricEnrollment, isFalse);
    });

    test('defaults to a silent key with enrollment invalidation on', () async {
      host.generateResult = GenerateResultWire(
        handleId: 'k',
        report: _report(SecurityLevelWire.secureEnclave),
      );

      await signet.generateKey(alias: 'k');

      expect(host.lastGenerateSpec!.authRequirement, AuthRequirementWire.none);
      expect(host.lastGenerateSpec!.authValiditySeconds, isNull);
      expect(host.lastGenerateSpec!.invalidateOnBiometricEnrollment, isTrue);
    });
  });

  group('getSecurityTier', () {
    test('reconstructs a re-read report with null requested and authEnforced',
        () async {
      host.tierResult = SecurityTierReportWire(
        achieved: SecurityLevelWire.tee,
        meetsFloor: true,
        evidence: TierEvidenceWire.keyInfoReadback,
        invalidated: false,
        schemaVersion: 1,
      );

      final report = await signet.getSecurityTier(const KeyHandle('k'));

      expect(report.achieved, SecurityLevel.tee);
      expect(report.requested, isNull);
      expect(report.authEnforced, isNull);
      expect(report.evidence, TierEvidence.keyInfoReadback);
      expect(report.invalidated, isFalse);
    });

    test('maps a populated requested policy and authEnforced', () async {
      host.tierResult = SecurityTierReportWire(
        achieved: SecurityLevelWire.strongBox,
        requestedKind: TierPolicyKindWire.atLeast,
        requestedAtLeastClass: HardwareClassWire.discreteSecure,
        meetsFloor: true,
        evidence: TierEvidenceWire.keyInfoReadback,
        authEnforced: AuthClassWire.biometricOrDeviceCredential,
        invalidated: false,
        schemaVersion: 1,
      );

      final report = await signet.getSecurityTier(const KeyHandle('k'));

      expect(report.requested, isA<AtLeast>());
      expect((report.requested! as AtLeast).floor, HardwareClass.discreteSecure);
      expect(report.authEnforced, AuthClass.biometricOrDeviceCredential);
    });
  });

  group('sign', () {
    test('passes the digest and encoding and returns the signature', () async {
      final signature = Uint8List.fromList(List<int>.filled(64, 7));
      host.signResult = signature;
      final digest = Uint8List.fromList(List<int>.filled(32, 9));

      final out = await signet.sign(
        const KeyHandle('k'),
        digest,
        options: const SignOptions(encoding: SignEncoding.rawRS),
      );

      expect(out, signature);
      expect(host.lastSignDigest, digest);
      expect(host.lastSignOptions!.encoding, SignEncodingWire.rawRS);
    });

    test('a silent sign passes a null prompt', () async {
      host.signResult = Uint8List.fromList([1]);
      final digest = Uint8List.fromList(List<int>.filled(32, 9));

      await signet.sign(const KeyHandle('k'), digest);

      expect(host.lastSignPrompt, isNull);
    });

    test('a gated sign marshals the prompt', () async {
      host.signResult = Uint8List.fromList([1]);
      final digest = Uint8List.fromList(List<int>.filled(32, 9));

      await signet.sign(
        const KeyHandle('k'),
        digest,
        prompt: const AuthPrompt(
          title: 'Approve',
          subtitle: 'Sign the transaction',
          negativeButtonText: 'No',
          authRequirement: AuthRequirement.biometricOnly,
        ),
      );

      final prompt = host.lastSignPrompt;
      expect(prompt, isNotNull);
      expect(prompt!.title, 'Approve');
      expect(prompt.subtitle, 'Sign the transaction');
      expect(prompt.negativeButtonText, 'No');
      expect(prompt.authRequirement, AuthRequirementWire.biometricOnly);
    });
  });

  group('getPublicKey', () {
    test('maps the format both ways', () async {
      host.publicKeyResult = PublicKeyWire(
        format: PublicKeyFormatWire.spki,
        bytes: Uint8List.fromList([4, 5]),
      );

      final publicKey =
          await signet.getPublicKey(const KeyHandle('k'), format: PublicKeyFormat.spki);

      expect(host.lastPublicKeyFormat, PublicKeyFormatWire.spki);
      expect(publicKey.format, PublicKeyFormat.spki);
      expect(publicKey.bytes, Uint8List.fromList([4, 5]));
    });
  });

  group('getAttestation', () {
    test('none yields a null chain', () async {
      host.attestationResult = AttestationResultWire(
        format: AttestationFormatWire.none,
        schemaVersion: 1,
      );

      final attestation = await signet.getAttestation(const KeyHandle('k'));

      expect(attestation.format, AttestationFormat.none);
      expect(attestation.chain, isNull);
    });

    test('androidKeyChain yields a typed certificate list', () async {
      host.attestationResult = AttestationResultWire(
        format: AttestationFormatWire.androidKeyChain,
        chain: <Uint8List?>[
          Uint8List.fromList([1]),
          Uint8List.fromList([2]),
        ],
        schemaVersion: 1,
      );

      final attestation = await signet.getAttestation(const KeyHandle('k'));

      expect(attestation.format, AttestationFormat.androidKeyChain);
      expect(attestation.chain, isNotNull);
      expect(attestation.chain!.length, 2);
      expect(attestation.chain!.first, Uint8List.fromList([1]));
    });
  });

  group('exists and delete', () {
    test('exists forwards the alias and returns the result', () async {
      host.existsResult = true;

      expect(await signet.exists('wallet'), isTrue);
      expect(host.lastAlias, 'wallet');
    });

    test('delete forwards the alias', () async {
      await signet.delete('wallet');

      expect(host.lastAlias, 'wallet');
    });
  });

  group('error mapping', () {
    test('maps every closed-set token to its code', () async {
      for (final expected in SignetErrorCode.values) {
        host.error = PlatformException(code: expected.name);
        await expectLater(
          signet.exists('k'),
          throwsA(isA<SignetException>().having((e) => e.code, 'code', expected)),
        );
      }
    });

    test('maps an unrecognized code to hardwareError', () async {
      host.error = PlatformException(code: 'somethingNew');

      await expectLater(
        signet.exists('k'),
        throwsA(
          isA<SignetException>()
              .having((e) => e.code, 'code', SignetErrorCode.hardwareError),
        ),
      );
    });

    test('carries the platform message', () async {
      host.error = PlatformException(code: 'notFound', message: 'no key');

      await expectLater(
        signet.exists('k'),
        throwsA(isA<SignetException>().having((e) => e.message, 'message', 'no key')),
      );
    });
  });
}

SecurityTierReportWire _report(SecurityLevelWire achieved) =>
    SecurityTierReportWire(
      achieved: achieved,
      meetsFloor: true,
      evidence: achieved == SecurityLevelWire.secureEnclave
          ? TierEvidenceWire.seTokenPresent
          : TierEvidenceWire.keyInfoReadback,
      invalidated: false,
      schemaVersion: 1,
    );

/// A host that records inputs and returns canned wire results, exercising the
/// idiomatic mapping and error layer without a native side.
class _FakeHost extends SignetHostApi {
  _FakeHost();

  KeySpecWire? lastGenerateSpec;
  Uint8List? lastSignDigest;
  SignOptionsWire? lastSignOptions;
  AuthPromptWire? lastSignPrompt;
  PublicKeyFormatWire? lastPublicKeyFormat;
  String? lastAlias;

  GenerateResultWire? generateResult;
  PublicKeyWire? publicKeyResult;
  Uint8List? signResult;
  AttestationResultWire? attestationResult;
  SecurityTierReportWire? tierResult;
  bool existsResult = false;
  PlatformException? error;

  @override
  Future<GenerateResultWire> generateKey(KeySpecWire spec) async {
    lastGenerateSpec = spec;
    if (error != null) throw error!;
    return generateResult!;
  }

  @override
  Future<PublicKeyWire> getPublicKey(
    String handleId,
    PublicKeyFormatWire format,
  ) async {
    lastPublicKeyFormat = format;
    if (error != null) throw error!;
    return publicKeyResult!;
  }

  @override
  Future<Uint8List> sign(
    String handleId,
    Uint8List digest,
    SignOptionsWire options,
    AuthPromptWire? prompt,
  ) async {
    lastSignDigest = digest;
    lastSignOptions = options;
    lastSignPrompt = prompt;
    if (error != null) throw error!;
    return signResult!;
  }

  @override
  Future<AttestationResultWire> getAttestation(String handleId) async {
    if (error != null) throw error!;
    return attestationResult!;
  }

  @override
  Future<SecurityTierReportWire> getSecurityTier(String handleId) async {
    if (error != null) throw error!;
    return tierResult!;
  }

  @override
  Future<bool> exists(String alias) async {
    lastAlias = alias;
    if (error != null) throw error!;
    return existsResult;
  }

  @override
  Future<void> deleteKey(String alias) async {
    lastAlias = alias;
    if (error != null) throw error!;
  }
}
