// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

/// Signet: hardware-backed P-256 signing keys via the native Secure Enclave and
/// Android Keystore cores.
///
/// This library is a thin channel over those cores. It holds no policy and no
/// key material: every decision that could downgrade a tier, overwrite a key, or
/// expose a private key is made in the native core, and Dart only marshals the
/// request and rebuilds the typed result. The private key has no export path on
/// any surface here.
library;

import 'dart:typed_data';

import 'package:flutter/foundation.dart' show visibleForTesting;
import 'package:flutter/services.dart' show PlatformException;

import 'src/messages.g.dart';

/// The hardware backing a signing key, reported as the achieved level and never
/// assumed from the request.
enum SecurityLevel { secureEnclave, strongBox, tee }

/// How the achieved [SecurityLevel] was determined.
enum TierEvidence { keyInfoReadback, seTokenPresent }

/// The presence check requested for a key at generation. Three values; [none]
/// creates a silent key. Distinct from [AuthClass], the four-value class read
/// back from the created key.
enum AuthRequirement { none, biometricOnly, biometricOrDeviceCredential }

/// The presence check bound to a key at creation, derived from the created key
/// and never echoed from the request.
enum AuthClass {
  none,
  biometricOnly,
  biometricOrDeviceCredential,
  deviceCredentialOnly,
}

/// A class in the tier partial order. [discreteSecure] covers Secure Enclave and
/// StrongBox, and outranks [trustedEnvironment].
enum HardwareClass { discreteSecure, trustedEnvironment }

/// The signature wire encoding.
enum SignEncoding { der, rawRS }

/// The public-key wire format.
enum PublicKeyFormat { rawX962, spki }

/// The attestation wire format.
enum AttestationFormat { androidKeyChain, none }

/// Tier selection by class, never a concrete [SecurityLevel]. The achieved level
/// is reported in [SecurityTierReport.achieved].
///
/// Ordering is a partial order over classes: `discreteSecure {secureEnclave,
/// strongBox} > trustedEnvironment {tee}`.
sealed class TierPolicy {
  const TierPolicy();
}

/// The strongest hardware tier available. Fails
/// [SignetErrorCode.unavailableTier] when no secure hardware is reachable; never
/// produces a software-backed key.
class Strongest extends TierPolicy {
  const Strongest();
}

/// A hard floor by class. Fails [SignetErrorCode.unavailableTier] below the class.
class AtLeast extends TierPolicy {
  const AtLeast(this.floor);

  final HardwareClass floor;
}

/// One report shape for every operation that reads a key's tier. [requested] and
/// [authEnforced] are null on a `getSecurityTier` re-read, where the policy is not
/// stored with the key and the platform may not read the created access control
/// back. A null [authEnforced] means unobservable, distinct from [AuthClass.none].
class SecurityTierReport {
  const SecurityTierReport({
    required this.achieved,
    required this.requested,
    required this.evidence,
    required this.authEnforced,
    required this.invalidated,
    this.schemaVersion = 1,
  });

  final SecurityLevel achieved;
  final TierPolicy? requested;
  final TierEvidence evidence;
  final AuthClass? authEnforced;
  final bool invalidated;
  final int schemaVersion;
}

/// Options for [Signet.sign].
class SignOptions {
  const SignOptions({this.encoding = SignEncoding.der});

  final SignEncoding encoding;
}

/// The prompt for an auth-gated [Signet.sign]. Supplied only for a gated key; the
/// native side presents it and authenticates the hardware key directly. The
/// [authRequirement] must match the key's and selects the prompt's authenticators.
class AuthPrompt {
  const AuthPrompt({
    required this.title,
    this.subtitle,
    this.negativeButtonText = 'Cancel',
    required this.authRequirement,
  });

  final String title;
  final String? subtitle;

  /// The fallback button label on a biometric-only prompt.
  final String negativeButtonText;

  final AuthRequirement authRequirement;
}

/// The attestation for a key: a certificate chain ([AttestationFormat.androidKeyChain]),
/// one DER-encoded certificate per element, or [AttestationFormat.none] with a null
/// chain. Produced, never verified, by this library.
class AttestationResult {
  const AttestationResult({
    required this.format,
    required this.chain,
    this.schemaVersion = 1,
  });

  final AttestationFormat format;
  final List<Uint8List>? chain;
  final int schemaVersion;
}

/// A public key in one of the pinned formats. There is no matching private-key
/// surface anywhere in this library.
class PublicKey {
  const PublicKey({required this.format, required this.bytes});

  final PublicKeyFormat format;
  final Uint8List bytes;
}

/// An opaque handle to a generated key. It carries only an id and no key
/// material; the private key never leaves hardware. A handle is reconstructible
/// from its id; a caller that persisted the id can rebuild it.
class KeyHandle {
  const KeyHandle(this.id);

  final String id;
}

/// The one closed error set. Every binding raises these exact names; spelling is
/// pinned (`userCanceled`, one `l`).
enum SignetErrorCode {
  unavailableTier,
  userCanceled,
  keyInvalidated,
  authFailed,
  authContextRequired,
  notFound,
  keyAlreadyExists,
  tierMismatchOnExisting,
  attestationUnsupported,
  hardwareError,
  unsupportedPlatform,
  invalidArgument,
  authInProgress,
}

/// The exception every Signet operation throws, carrying one [SignetErrorCode].
/// Callers match on [code] structurally; the code is never string-matched.
class SignetException implements Exception {
  const SignetException(this.code, [this.message]);

  final SignetErrorCode code;
  final String? message;

  @override
  String toString() =>
      'SignetException(${code.name}${message == null ? '' : ': $message'})';
}

/// Hardware-backed P-256 signing keys.
///
/// Keys are silent by default or carry a presence check via [AuthRequirement]; a
/// gated key is signed by passing an [AuthPrompt], which the native side presents
/// and authenticates directly. Every call marshals to the native core and rebuilds
/// the typed result; a core error arrives as a [SignetException] over the closed
/// [SignetErrorCode] set.
class Signet {
  /// Binds to the platform channel over the native core.
  Signet() : _host = SignetHostApi();

  /// Injects a host for unit tests. Not part of the public surface.
  @visibleForTesting
  Signet.withHostApi(this._host);

  final SignetHostApi _host;

  /// Generates a non-exportable P-256 key at [alias]. [tierPolicy] selects by
  /// class (default [Strongest]); a policy below its floor fails
  /// [SignetErrorCode.unavailableTier] and no key is kept. [authRequirement] binds
  /// a presence check to the key (default [AuthRequirement.none], a silent key); a
  /// gated key
  /// needs an [AuthPrompt] at [sign]. [authValiditySeconds] sets an auth reuse
  /// window (null and 0 mean per-use); [invalidateOnBiometricEnrollment] makes a
  /// later biometric enrollment invalidate the key. An existing alias fails
  /// [SignetErrorCode.keyAlreadyExists] with no silent overwrite. An
  /// [attestationChallenge] is bound into the key here; [getAttestation] takes
  /// none. Returns the handle and its report together.
  Future<(KeyHandle, SecurityTierReport)> generateKey({
    required String alias,
    TierPolicy tierPolicy = const Strongest(),
    AuthRequirement authRequirement = AuthRequirement.none,
    int? authValiditySeconds,
    bool invalidateOnBiometricEnrollment = true,
    Uint8List? attestationChallenge,
  }) async {
    final result = await _guard(
      () => _host.generateKey(
        KeySpecWire(
          alias: alias,
          tierPolicyKind: _tierKindTo(tierPolicy),
          atLeastClass:
              tierPolicy is AtLeast ? _hardwareClassTo(tierPolicy.floor) : null,
          authRequirement: _authRequirementTo(authRequirement),
          authValiditySeconds: authValiditySeconds,
          invalidateOnBiometricEnrollment: invalidateOnBiometricEnrollment,
          attestationChallenge: attestationChallenge,
        ),
      ),
    );
    return (KeyHandle(result.handleId), _reportFrom(result.report));
  }

  /// Public key only. The private key has no export path.
  Future<PublicKey> getPublicKey(
    KeyHandle handle, {
    PublicKeyFormat format = PublicKeyFormat.rawX962,
  }) async {
    final result =
        await _guard(() => _host.getPublicKey(handle.id, _pubFormatTo(format)));
    return PublicKey(format: _pubFormatFrom(result.format), bytes: result.bytes);
  }

  /// Signs a 32-byte digest (`NONEwithECDSA` / `ecdsaSignatureDigestX962SHA256`).
  /// With no [prompt] this is the silent path and raises no prompt. Pass a
  /// [prompt] for a gated key: the native side presents the biometric prompt
  /// itself and authenticates the hardware key directly, with no Dart round-trip.
  /// A wrong-length digest fails [SignetErrorCode.invalidArgument] before any key
  /// access. A second concurrent gated sign fails
  /// [SignetErrorCode.authInProgress]; a gated key with no presentable host UI
  /// fails [SignetErrorCode.authContextRequired], never
  /// [SignetErrorCode.hardwareError].
  Future<Uint8List> sign(
    KeyHandle handle,
    Uint8List digest, {
    SignOptions options = const SignOptions(),
    AuthPrompt? prompt,
  }) {
    return _guard(
      () => _host.sign(
        handle.id,
        digest,
        SignOptionsWire(encoding: _encodingTo(options.encoding)),
        prompt == null ? null : _authPromptTo(prompt),
      ),
    );
  }

  /// Attestation is produced, never verified, by this library. The challenge was
  /// bound at [generateKey]; this call takes none. The format is
  /// [AttestationFormat.androidKeyChain] (Android) or [AttestationFormat.none]
  /// (Apple Secure Enclave has no per-key attestation).
  Future<AttestationResult> getAttestation(KeyHandle handle) async {
    final result = await _guard(() => _host.getAttestation(handle.id));
    return AttestationResult(
      format: _attestationFormatFrom(result.format),
      chain: result.chain?.whereType<Uint8List>().toList(growable: false),
      schemaVersion: result.schemaVersion,
    );
  }

  /// Re-reads a key's tier. Does not throw on an invalidated-but-present key: the
  /// report's `invalidated == true`.
  Future<SecurityTierReport> getSecurityTier(KeyHandle handle) async {
    final result = await _guard(() => _host.getSecurityTier(handle.id));
    return _reportFrom(result);
  }

  /// Whether a key exists for [alias].
  Future<bool> exists(String alias) => _guard(() => _host.exists(alias));

  /// Deletes the key for [alias]. Idempotent: a missing alias is not an error.
  Future<void> delete(String alias) => _guard(() => _host.deleteKey(alias));

  /// Runs a channel call and maps a platform error's code to a [SignetException]
  /// over the closed set. An unrecognized code maps to
  /// [SignetErrorCode.hardwareError]; the conformance suite asserts the wire set
  /// is exactly the closed set, so a new native code cannot masquerade unnoticed.
  Future<T> _guard<T>(Future<T> Function() call) async {
    try {
      return await call();
    } on PlatformException catch (error) {
      throw SignetException(_codeFrom(error.code), error.message);
    }
  }

  SecurityTierReport _reportFrom(SecurityTierReportWire wire) {
    return SecurityTierReport(
      achieved: _securityLevelFrom(wire.achieved),
      requested: _tierPolicyFrom(wire.requestedKind, wire.requestedAtLeastClass),
      evidence: _evidenceFrom(wire.evidence),
      authEnforced:
          wire.authEnforced == null ? null : _authClassFrom(wire.authEnforced!),
      invalidated: wire.invalidated,
      schemaVersion: wire.schemaVersion,
    );
  }
}

SignetErrorCode _codeFrom(String code) {
  for (final candidate in SignetErrorCode.values) {
    if (candidate.name == code) return candidate;
  }
  return SignetErrorCode.hardwareError;
}

TierPolicyKindWire _tierKindTo(TierPolicy policy) => switch (policy) {
      Strongest() => TierPolicyKindWire.strongest,
      AtLeast() => TierPolicyKindWire.atLeast,
    };

TierPolicy? _tierPolicyFrom(
  TierPolicyKindWire? kind,
  HardwareClassWire? atLeastClass,
) =>
    switch (kind) {
      null => null,
      TierPolicyKindWire.strongest => const Strongest(),
      TierPolicyKindWire.atLeast => AtLeast(_hardwareClassFrom(atLeastClass!)),
    };

HardwareClassWire _hardwareClassTo(HardwareClass value) => switch (value) {
      HardwareClass.discreteSecure => HardwareClassWire.discreteSecure,
      HardwareClass.trustedEnvironment => HardwareClassWire.trustedEnvironment,
    };

HardwareClass _hardwareClassFrom(HardwareClassWire value) => switch (value) {
      HardwareClassWire.discreteSecure => HardwareClass.discreteSecure,
      HardwareClassWire.trustedEnvironment => HardwareClass.trustedEnvironment,
    };

SecurityLevel _securityLevelFrom(SecurityLevelWire value) => switch (value) {
      SecurityLevelWire.secureEnclave => SecurityLevel.secureEnclave,
      SecurityLevelWire.strongBox => SecurityLevel.strongBox,
      SecurityLevelWire.tee => SecurityLevel.tee,
    };

TierEvidence _evidenceFrom(TierEvidenceWire value) => switch (value) {
      TierEvidenceWire.keyInfoReadback => TierEvidence.keyInfoReadback,
      TierEvidenceWire.seTokenPresent => TierEvidence.seTokenPresent,
    };

AuthClass _authClassFrom(AuthClassWire value) => switch (value) {
      AuthClassWire.none => AuthClass.none,
      AuthClassWire.biometricOnly => AuthClass.biometricOnly,
      AuthClassWire.biometricOrDeviceCredential =>
        AuthClass.biometricOrDeviceCredential,
      AuthClassWire.deviceCredentialOnly => AuthClass.deviceCredentialOnly,
    };

SignEncodingWire _encodingTo(SignEncoding value) => switch (value) {
      SignEncoding.der => SignEncodingWire.der,
      SignEncoding.rawRS => SignEncodingWire.rawRS,
    };

AuthRequirementWire _authRequirementTo(AuthRequirement value) => switch (value) {
      AuthRequirement.none => AuthRequirementWire.none,
      AuthRequirement.biometricOnly => AuthRequirementWire.biometricOnly,
      AuthRequirement.biometricOrDeviceCredential =>
        AuthRequirementWire.biometricOrDeviceCredential,
    };

AuthPromptWire _authPromptTo(AuthPrompt value) => AuthPromptWire(
      title: value.title,
      subtitle: value.subtitle,
      negativeButtonText: value.negativeButtonText,
      authRequirement: _authRequirementTo(value.authRequirement),
    );

PublicKeyFormatWire _pubFormatTo(PublicKeyFormat value) => switch (value) {
      PublicKeyFormat.rawX962 => PublicKeyFormatWire.rawX962,
      PublicKeyFormat.spki => PublicKeyFormatWire.spki,
    };

PublicKeyFormat _pubFormatFrom(PublicKeyFormatWire value) => switch (value) {
      PublicKeyFormatWire.rawX962 => PublicKeyFormat.rawX962,
      PublicKeyFormatWire.spki => PublicKeyFormat.spki,
    };

AttestationFormat _attestationFormatFrom(AttestationFormatWire value) =>
    switch (value) {
      AttestationFormatWire.androidKeyChain => AttestationFormat.androidKeyChain,
      AttestationFormatWire.none => AttestationFormat.none,
    };
