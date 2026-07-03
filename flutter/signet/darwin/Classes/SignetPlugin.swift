// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

#if os(macOS)
  import FlutterMacOS
#else
  import Flutter
#endif
import Foundation
import SignetAppleCore

/// Flutter plugin entry point for the Signet Darwin binding (iOS and macOS).
///
/// Registers the generated `SignetHostApi` and forwards every call to
/// `SecureEnclaveKeyStore` in the `apple/` core. This class holds no policy and no
/// key material; the core is the only code that touches the Secure Enclave.
public class SignetPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    #if os(macOS)
      let messenger = registrar.messenger
    #else
      let messenger = registrar.messenger()
    #endif
    SignetHostApiSetup.setUp(binaryMessenger: messenger, api: SignetHostApiImpl())
  }
}

/// Bridges the generated host API to the core. Every call maps a `SignetError`
/// into a Pigeon error carrying the closed-set code; wire structs map one-to-one
/// to the core's canonical types.
final class SignetHostApiImpl: SignetHostApi {
  private let store = SecureEnclaveKeyStore()

  func generateKey(spec: KeySpecWire) throws -> GenerateResultWire {
    try coded {
      let (handle, report) = try store.generateKey(spec.toKeySpec())
      return GenerateResultWire(handleId: handle.alias, report: report.toWire())
    }
  }

  func getPublicKey(handleId: String, format: PublicKeyFormatWire) throws -> PublicKeyWire {
    try coded {
      let publicKey = try store.getPublicKey(KeyHandle(alias: handleId), format: format.toCore())
      return PublicKeyWire(
        format: publicKey.format.toWire(),
        bytes: FlutterStandardTypedData(bytes: publicKey.bytes)
      )
    }
  }

  func sign(
    handleId: String,
    digest: FlutterStandardTypedData,
    options: SignOptionsWire,
    completion: @escaping (Result<FlutterStandardTypedData, Error>) -> Void
  ) {
    do {
      let signature = try store.sign(
        KeyHandle(alias: handleId),
        digest: digest.data,
        options: options.toCore()
      )
      completion(.success(FlutterStandardTypedData(bytes: signature)))
    } catch let error as SignetError {
      completion(.failure(error.asPigeonError))
    } catch {
      completion(.failure(SignetError.hardwareError.asPigeonError))
    }
  }

  func getAttestation(handleId: String) throws -> AttestationResultWire {
    try coded { try store.getAttestation(KeyHandle(alias: handleId)).toWire() }
  }

  func getSecurityTier(handleId: String) throws -> SecurityTierReportWire {
    try coded { try store.getSecurityTier(KeyHandle(alias: handleId)).toWire() }
  }

  func exists(alias: String) throws -> Bool {
    store.exists(alias: alias)
  }

  func deleteKey(alias: String) throws {
    try coded { try store.delete(alias: alias) }
  }
}

/// Runs a core call, translating a `SignetError` into the Pigeon error carrying
/// its closed-set code. A non-`SignetError` maps to `hardwareError`. The core
/// raises only the closed set; this catch is the defensive floor, not a live path.
private func coded<T>(_ block: () throws -> T) throws -> T {
  do {
    return try block()
  } catch let error as SignetError {
    throw error.asPigeonError
  } catch let error as PigeonError {
    throw error
  } catch {
    throw SignetError.hardwareError.asPigeonError
  }
}

private extension SignetError {
  /// The closed-set wire token for this case. Pinned to `conformance/errors.json`;
  /// spelled explicitly rather than reflected, so a rename cannot drift the wire.
  var code: String {
    switch self {
    case .unavailableTier: return "unavailableTier"
    case .userCanceled: return "userCanceled"
    case .keyInvalidated: return "keyInvalidated"
    case .authFailed: return "authFailed"
    case .authContextRequired: return "authContextRequired"
    case .notFound: return "notFound"
    case .keyAlreadyExists: return "keyAlreadyExists"
    case .tierMismatchOnExisting: return "tierMismatchOnExisting"
    case .attestationUnsupported: return "attestationUnsupported"
    case .hardwareError: return "hardwareError"
    case .unsupportedPlatform: return "unsupportedPlatform"
    case .invalidArgument: return "invalidArgument"
    case .authInProgress: return "authInProgress"
    }
  }

  var asPigeonError: PigeonError {
    PigeonError(code: code, message: nil, details: nil)
  }
}

// ---- wire -> core ----

private extension KeySpecWire {
  func toKeySpec() throws -> KeySpec {
    let policy: TierPolicy
    switch tierPolicyKind {
    case .strongest:
      policy = .strongest
    case .atLeast:
      guard let atLeastClass else { throw SignetError.invalidArgument }
      policy = .atLeast(atLeastClass.toCore())
    case .bestEffort:
      policy = .bestEffort
    }
    // The Secure Enclave exposes no per-key attestation, so the wire challenge has
    // no effect on Apple; getAttestation returns format none regardless.
    return KeySpec(alias: alias, tierPolicy: policy, accessControl: .none)
  }
}

private extension HardwareClassWire {
  func toCore() -> HardwareClass {
    switch self {
    case .discreteSecure: return .discreteSecure
    case .trustedEnvironment: return .trustedEnvironment
    }
  }
}

private extension PublicKeyFormatWire {
  func toCore() -> PublicKey.Format {
    switch self {
    case .rawX962: return .rawX962
    case .spki: return .spki
    }
  }
}

private extension SignOptionsWire {
  func toCore() -> SignOptions {
    switch encoding {
    case .der: return SignOptions(encoding: .der)
    case .rawRS: return SignOptions(encoding: .rawRS)
    }
  }
}

// ---- core -> wire ----

private extension SecurityTierReport {
  func toWire() -> SecurityTierReportWire {
    let (requestedKind, requestedAtLeastClass) = requestedToWire(requested)
    return SecurityTierReportWire(
      achieved: achieved.toWire(),
      requestedKind: requestedKind,
      requestedAtLeastClass: requestedAtLeastClass,
      meetsFloor: meetsFloor,
      evidence: evidence.toWire(),
      authEnforced: authEnforced?.toWire(),
      invalidated: invalidated,
      schemaVersion: Int64(schemaVersion)
    )
  }
}

private func requestedToWire(
  _ policy: TierPolicy?
) -> (TierPolicyKindWire?, HardwareClassWire?) {
  switch policy {
  case nil: return (nil, nil)
  case .strongest?: return (.strongest, nil)
  case .atLeast(let hardwareClass)?: return (.atLeast, hardwareClass.toWire())
  case .bestEffort?: return (.bestEffort, nil)
  }
}

private extension AttestationResult {
  func toWire() -> AttestationResultWire {
    let wireFormat: AttestationFormatWire
    switch format {
    case .androidKeyChain: wireFormat = .androidKeyChain
    case .none: wireFormat = .none
    }
    let wireChain: [FlutterStandardTypedData?]? =
      chain.isEmpty ? nil : chain.map { FlutterStandardTypedData(bytes: $0) }
    return AttestationResultWire(
      format: wireFormat,
      chain: wireChain,
      schemaVersion: Int64(schemaVersion)
    )
  }
}

private extension SecurityLevel {
  func toWire() -> SecurityLevelWire {
    switch self {
    case .secureEnclave: return .secureEnclave
    case .strongBox: return .strongBox
    case .tee: return .tee
    case .tpm: return .tpm
    case .software: return .software
    }
  }
}

private extension TierEvidence {
  func toWire() -> TierEvidenceWire {
    switch self {
    case .attested: return .attested
    case .keyInfoReadback: return .keyInfoReadback
    case .seTokenPresent: return .seTokenPresent
    case .inferred: return .inferred
    case .selfReportUnverified: return .selfReportUnverified
    }
  }
}

private extension AuthClass {
  func toWire() -> AuthClassWire {
    switch self {
    case .none: return .none
    case .biometricOnly: return .biometricOnly
    case .biometricOrDeviceCredential: return .biometricOrDeviceCredential
    case .deviceCredentialOnly: return .deviceCredentialOnly
    }
  }
}

private extension HardwareClass {
  func toWire() -> HardwareClassWire {
    switch self {
    case .discreteSecure: return .discreteSecure
    case .trustedEnvironment: return .trustedEnvironment
    }
  }
}

private extension PublicKey.Format {
  func toWire() -> PublicKeyFormatWire {
    switch self {
    case .rawX962: return .rawX962
    case .spki: return .spki
    }
  }
}
