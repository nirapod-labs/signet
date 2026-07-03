// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(
  PigeonOptions(
    dartOut: 'lib/src/messages.g.dart',
    kotlinOut: 'android/src/main/kotlin/xyz/nirapod/signet/Messages.g.kt',
    kotlinOptions: KotlinOptions(package: 'xyz.nirapod.signet'),
    swiftOut: 'darwin/Classes/Messages.g.swift',
    dartPackageName: 'signet',
    copyrightHeader: 'pigeons/copyright.txt',
  ),
)

/// Hardware backing a key, reported as achieved and never assumed from the
/// request. Crosses the channel as a pinned token, not an ordinal.
enum SecurityLevelWire { secureEnclave, strongBox, tee, tpm, software }

/// How the achieved level was determined. Only `attested` is cryptographic
/// proof; every other value is an on-device self-report.
enum TierEvidenceWire {
  attested,
  keyInfoReadback,
  seTokenPresent,
  inferred,
  selfReportUnverified,
}

/// The tier-selection policy kind. `atLeast` carries its class in [KeySpecWire].
enum TierPolicyKindWire { strongest, atLeast, bestEffort }

/// A class in the tier partial order; `discreteSecure` outranks
/// `trustedEnvironment`.
enum HardwareClassWire { discreteSecure, trustedEnvironment }

/// The presence check REQUESTED for a key at generation. Three values; `none`
/// is a silent key. Distinct from [AuthClassWire], the four-value class read
/// back from the created key and reported in a tier report.
enum AuthRequirementWire { none, biometricOnly, biometricOrDeviceCredential }

/// The presence check bound to a created key, reported in a tier report.
enum AuthClassWire {
  none,
  biometricOnly,
  biometricOrDeviceCredential,
  deviceCredentialOnly,
}

/// Public-key wire format: uncompressed X9.63 point or DER SubjectPublicKeyInfo.
enum PublicKeyFormatWire { rawX962, spki }

/// Attestation wire format: a certificate chain or none.
enum AttestationFormatWire { androidKeyChain, none }

/// Signature wire encoding: X9.62 DER or fixed 64-byte r||s.
enum SignEncodingWire { der, rawRS }

/// A key-generation request. The achieved tier and auth class are read back from
/// the created key, never assumed from the request.
class KeySpecWire {
  KeySpecWire({
    required this.alias,
    required this.tierPolicyKind,
    this.atLeastClass,
    required this.authRequirement,
    this.authValiditySeconds,
    required this.invalidateOnBiometricEnrollment,
    this.attestationChallenge,
  });

  /// Stable, app-scoped name for the key.
  final String alias;

  /// Tier selection kind.
  final TierPolicyKindWire tierPolicyKind;

  /// Set only when [tierPolicyKind] is `atLeast`; null otherwise.
  final HardwareClassWire? atLeastClass;

  /// The presence check to bind to the key; `none` creates a silent key.
  final AuthRequirementWire authRequirement;

  /// Auth reuse window in seconds; null and 0 both mean per-use. Baked into the
  /// key where the platform supports it (Android); a sign-time value elsewhere.
  final int? authValiditySeconds;

  /// Whether a biometric re-enrollment invalidates the key.
  final bool invalidateOnBiometricEnrollment;

  /// Bound into the key at generation; there is no call-time challenge.
  final Uint8List? attestationChallenge;
}

/// One report shape for every operation that reads a key's tier. `requested` and
/// `authEnforced` are null on a re-read, where the policy is not stored with the
/// key and the platform may not read the created access control back.
class SecurityTierReportWire {
  SecurityTierReportWire({
    required this.achieved,
    this.requestedKind,
    this.requestedAtLeastClass,
    required this.meetsFloor,
    required this.evidence,
    this.authEnforced,
    required this.invalidated,
    required this.schemaVersion,
  });

  final SecurityLevelWire achieved;
  final TierPolicyKindWire? requestedKind;
  final HardwareClassWire? requestedAtLeastClass;
  final bool meetsFloor;
  final TierEvidenceWire evidence;
  final AuthClassWire? authEnforced;
  final bool invalidated;
  final int schemaVersion;
}

/// Options for a signature.
class SignOptionsWire {
  SignOptionsWire({required this.encoding});

  final SignEncodingWire encoding;
}

/// The attestation for a key: a certificate chain (`androidKeyChain`), one
/// DER-encoded certificate per element, or `none` with a null chain. The library
/// produces attestation and never verifies it.
class AttestationResultWire {
  AttestationResultWire({
    required this.format,
    this.chain,
    required this.schemaVersion,
  });

  final AttestationFormatWire format;
  final List<Uint8List?>? chain;
  final int schemaVersion;
}

/// The result of generating a key: an opaque handle id carrying no key material,
/// and the tier report read back from the created key.
class GenerateResultWire {
  GenerateResultWire({required this.handleId, required this.report});

  final String handleId;
  final SecurityTierReportWire report;
}

/// A public key in one of the pinned formats. There is no matching private-key
/// surface anywhere in the contract.
class PublicKeyWire {
  PublicKeyWire({required this.format, required this.bytes});

  final PublicKeyFormatWire format;
  final Uint8List bytes;
}

/// The prompt for an auth-gated sign, non-null on [SignetHostApi.sign] only for a
/// gated key. The native side presents it and authenticates the hardware key
/// directly; a Dart-shown prompt could not. [authRequirement] must match the
/// key's and selects the prompt's authenticators.
class AuthPromptWire {
  AuthPromptWire({
    required this.title,
    this.subtitle,
    required this.negativeButtonText,
    required this.authRequirement,
  });

  final String title;
  final String? subtitle;

  /// The fallback button label on a biometric-only prompt.
  final String negativeButtonText;

  /// Selects the prompt's authenticators; matches the key's requirement.
  final AuthRequirementWire authRequirement;
}

/// The calls Dart makes into the native core. Errors do not cross as data: the
/// core throws a platform error whose code is one of the closed error tokens in
/// `conformance/errors.json`, which the idiomatic layer maps to a typed
/// exception. The native side is not more trusted than Dart; both run in the
/// same process and the only trust anchors are the hardware and a remote
/// attestation verifier this library never calls.
@HostApi()
abstract class SignetHostApi {
  /// Generates a non-exportable P-256 key. Fails `keyAlreadyExists` on an
  /// existing alias, `unavailableTier` when a hard policy cannot be met.
  GenerateResultWire generateKey(KeySpecWire spec);

  /// Public key only; the private key has no export path.
  PublicKeyWire getPublicKey(String handleId, PublicKeyFormatWire format);

  /// Signs a 32-byte digest. A null [prompt] is the silent path and raises no
  /// prompt; a non-null [prompt] drives an auth-gated sign whose biometric prompt
  /// the native side presents and authenticates directly. A wrong-length digest
  /// is rejected `invalidArgument` before any key access. A second concurrent
  /// gated sign is rejected `authInProgress`; a gated key with no presentable host
  /// UI raises `authContextRequired`.
  @async
  Uint8List sign(
    String handleId,
    Uint8List digest,
    SignOptionsWire options,
    AuthPromptWire? prompt,
  );

  /// Attestation bound at generation; takes no call-time challenge.
  AttestationResultWire getAttestation(String handleId);

  /// Re-reads a key's tier; does not throw on an invalidated-but-present key.
  SecurityTierReportWire getSecurityTier(String handleId);

  /// Whether a key exists for the alias.
  bool exists(String alias);

  /// Deletes the key for the alias. Idempotent: a missing alias is not an error.
  void deleteKey(String alias);
}
