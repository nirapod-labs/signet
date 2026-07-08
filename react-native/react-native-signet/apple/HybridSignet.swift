// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import NitroModules
import SignetCore

/// The Nitro HybridObject for iOS and macOS. Subclasses the generated
/// `HybridSignetSpec` and forwards every call to `SecureEnclaveKeyStore` in the
/// `apple/` core. It holds no policy and no key material; the core is the only code
/// that touches the Secure Enclave. A key is silent by default or carries a presence
/// check; a gated key is signed by passing an `AuthPrompt`, which the core presents
/// through the Secure Enclave and authenticates directly.
///
/// The generated Nitro wire types share short names with the core (`KeySpec`,
/// `SecurityTierReport`, ...); the core is always spelled `SignetCore.` here
/// and the unqualified names are the Nitro ones. Enums cross by their string token
/// (`stringValue` / `fromString`), never by the Nitro case name, whose casing
/// differs from the wire token.
final class HybridSignet: HybridSignetSpec {
  private let store = SecureEnclaveKeyStore()

  func generateKey(spec: KeySpec) throws -> GenerateResult {
    try coded {
      let (handle, report) = try store.generateKey(coreKeySpec(spec))
      return GenerateResult(handleId: handle.alias, report: nitroReport(report))
    }
  }

  func getPublicKey(handleId: String, format: PublicKeyFormat) throws -> PublicKeyData {
    try coded {
      let publicKey = try store.getPublicKey(KeyHandle(alias: handleId), format: coreFormat(format))
      return PublicKeyData(format: nitroFormat(publicKey.format), bytes: try ArrayBuffer.copy(data: publicKey.bytes))
    }
  }

  func sign(
    handleId: String,
    digest: ArrayBuffer,
    options: SignOptions,
    prompt: AuthPrompt?
  ) throws -> Promise<ArrayBuffer> {
    // Copy the digest out before the async hop; the buffer is only valid for the
    // synchronous call.
    let data = digest.toData(copyIfNeeded: true)
    let store = self.store
    let coreOptions = SignetCore.SignOptions(encoding: coreEncoding(options.encoding))
    guard let prompt else {
      // Silent path: no prompt, the synchronous core sign.
      return Promise.async {
        try coded {
          let signature = try store.sign(KeyHandle(alias: handleId), digest: data, options: coreOptions)
          return try ArrayBuffer.copy(data: signature)
        }
      }
    }
    // Gated path: the core presents the Enclave prompt off the main thread; await it.
    let corePrompt = coreAuthPrompt(prompt)
    return Promise.async {
      try await codedAsync {
        let signature = try await store.sign(
          KeyHandle(alias: handleId),
          digest: data,
          prompt: corePrompt,
          options: coreOptions
        )
        return try ArrayBuffer.copy(data: signature)
      }
    }
  }

  func getAttestation(handleId: String) throws -> AttestationResult {
    try coded { try nitroAttestation(store.getAttestation(KeyHandle(alias: handleId))) }
  }

  func getSecurityTier(handleId: String) throws -> SecurityTierReport {
    try coded { nitroReport(try store.getSecurityTier(KeyHandle(alias: handleId))) }
  }

  func exists(alias: String) throws -> Bool {
    store.exists(alias: alias)
  }

  func deleteKey(alias: String) throws {
    try coded { try store.delete(alias: alias) }
  }
}

// ---- error mapping ----

/// A thrown error whose message is one closed-set token. Nitro has no structured
/// error-code channel, so the token travels in the message; the idiomatic layer
/// maps it back to a typed SignetError.
private struct SignetHybridError: LocalizedError {
  let token: String
  var errorDescription: String? { token }
}

/// Runs a core call, translating a `SignetError` into the token-carrying hybrid
/// error. A non-`SignetError` fails closed to `hardwareError`.
private func coded<T>(_ block: () throws -> T) throws -> T {
  do {
    return try block()
  } catch let error as SignetError {
    throw SignetHybridError(token: error.token)
  } catch let error as SignetHybridError {
    throw error
  } catch {
    throw SignetHybridError(token: "hardwareError")
  }
}

/// The async form of `coded`, for the gated `sign`. A distinct name (rather than an
/// overload) keeps resolution unambiguous inside a `Promise.async` body.
private func codedAsync<T>(_ block: () async throws -> T) async throws -> T {
  do {
    return try await block()
  } catch let error as SignetError {
    throw SignetHybridError(token: error.token)
  } catch let error as SignetHybridError {
    throw error
  } catch {
    throw SignetHybridError(token: "hardwareError")
  }
}

private extension SignetError {
  /// The closed-set wire token for this case; pinned to `conformance/errors.json`.
  var token: String {
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
}

// ---- Nitro -> core (request side) ----

private func coreKeySpec(_ spec: KeySpec) throws -> SignetCore.KeySpec {
  let policy: TierPolicy
  switch spec.tierPolicyKind.stringValue {
  case "strongest":
    policy = .strongest
  case "atLeast":
    guard let atLeastClass = spec.atLeastClass else { throw SignetError.invalidArgument }
    policy = .atLeast(coreHardwareClass(atLeastClass))
  default:
    throw SignetError.invalidArgument
  }
  let accessControl = SignetCore.AccessControlPolicy(
    authRequirement: coreAuthRequirement(spec.authRequirement),
    authValiditySeconds: spec.authValiditySeconds.map { Int($0) },
    invalidateOnBiometricEnrollment: spec.invalidateOnBiometricEnrollment
  )
  // The Secure Enclave has no per-key attestation, so the wire challenge has no
  // effect on Apple; getAttestation returns none regardless.
  return SignetCore.KeySpec(alias: spec.alias, tierPolicy: policy, accessControl: accessControl)
}

private func coreHardwareClass(_ value: HardwareClass) -> SignetCore.HardwareClass {
  SignetCore.HardwareClass(rawValue: value.stringValue) ?? .discreteSecure
}

private func coreAuthRequirement(
  _ value: AuthRequirement
) -> SignetCore.AccessControlPolicy.AuthRequirement {
  SignetCore.AccessControlPolicy.AuthRequirement(rawValue: value.stringValue) ?? .none
}

private func coreAuthPrompt(_ prompt: AuthPrompt) -> SignetCore.AuthPrompt {
  SignetCore.AuthPrompt(
    title: prompt.title,
    subtitle: prompt.subtitle,
    negativeButtonText: prompt.negativeButtonText,
    authRequirement: coreAuthRequirement(prompt.authRequirement)
  )
}

private func coreFormat(_ value: PublicKeyFormat) -> PublicKey.Format {
  value.stringValue == "spki" ? .spki : .rawX962
}

private func coreEncoding(_ value: SignEncoding) -> SignetCore.SignOptions.Encoding {
  value.stringValue == "rawRS" ? .rawRS : .der
}

// ---- core -> Nitro (report side) ----

private func nitroReport(_ report: SignetCore.SecurityTierReport) -> SecurityTierReport {
  let (requestedKind, requestedAtLeastClass) = nitroRequested(report.requested)
  return SecurityTierReport(
    achieved: SecurityLevel(fromString: report.achieved.rawValue)!,
    requestedKind: requestedKind,
    requestedAtLeastClass: requestedAtLeastClass,
    evidence: TierEvidence(fromString: report.evidence.rawValue)!,
    authEnforced: report.authEnforced.map { AuthClass(fromString: $0.rawValue)! },
    invalidated: report.invalidated,
    schemaVersion: Double(report.schemaVersion)
  )
}

private func nitroRequested(_ policy: TierPolicy?) -> (TierPolicyKind?, HardwareClass?) {
  switch policy {
  case nil:
    return (nil, nil)
  case .strongest?:
    return (TierPolicyKind(fromString: "strongest")!, nil)
  case .atLeast(let hardwareClass)?:
    return (TierPolicyKind(fromString: "atLeast")!, HardwareClass(fromString: hardwareClass.rawValue)!)
  }
}

private func nitroFormat(_ value: PublicKey.Format) -> PublicKeyFormat {
  switch value {
  case .rawX962: return PublicKeyFormat(fromString: "rawX962")!
  case .spki: return PublicKeyFormat(fromString: "spki")!
  }
}

private func nitroAttestation(_ result: SignetCore.AttestationResult) throws -> AttestationResult {
  let format: AttestationFormat
  switch result.format {
  case .none: format = AttestationFormat(fromString: "none")!
  }
  let chain = result.chain.isEmpty ? nil : try result.chain.map { try ArrayBuffer.copy(data: $0) }
  return AttestationResult(format: format, chain: chain, schemaVersion: Double(result.schemaVersion))
}
