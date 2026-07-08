// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

/// The hardware backing a signing key, reported as the achieved level and never
/// assumed from the request. Closed set; see `conformance/security-level.json`.
/// The Apple core reaches only the Secure Enclave; when it is unavailable the
/// store fails closed and never produces a software-backed key.
public enum SecurityLevel: String, Sendable, Equatable, CaseIterable {
    case secureEnclave
}

/// How the achieved `SecurityLevel` was determined. On Apple the evidence is the
/// Secure Enclave token's presence at key creation.
public enum TierEvidence: String, Sendable, Equatable, CaseIterable {
    case seTokenPresent
}

/// The presence check bound to a key at creation, derived from the created
/// access control and never echoed from the request.
public enum AuthClass: String, Sendable, Equatable, CaseIterable {
    case none
    case biometricOnly
    case biometricOrDeviceCredential
    case deviceCredentialOnly
}

/// A class in the tier partial order. `atLeast(_:)` selects by class:
/// `discreteSecure` (the Secure Enclave on Apple) outranks `trustedEnvironment`.
public enum HardwareClass: String, Sendable, Equatable, CaseIterable {
    case discreteSecure
    case trustedEnvironment
}

/// Tier selection on `KeySpec`. Selection is by class, never a concrete
/// `SecurityLevel`; the achieved level is reported in `SecurityTierReport`.
public enum TierPolicy: Sendable, Equatable {
    /// The device's strongest hardware tier. Fails closed (`unavailableTier`)
    /// when no secure hardware is reachable; never produces a software-backed key.
    case strongest
    /// A hard floor by class. Fails closed (`unavailableTier`) below the class.
    case atLeast(HardwareClass)
}

extension SecurityLevel {
    /// The partial-order class this level belongs to. Total: every reachable
    /// level is hardware-backed.
    var hardwareClass: HardwareClass {
        switch self {
        case .secureEnclave: return .discreteSecure
        }
    }
}

/// One report shape everywhere. `achieved` is read back from the created key and
/// `authEnforced` is derived from the created access control.
///
/// `requested` and `authEnforced` are optional. `generateKey` populates both. A
/// `getSecurityTier` re-read leaves `requested` nil (the policy is not stored
/// with the key) and leaves `authEnforced` nil where the platform cannot read
/// the created access control back (Apple has no such read-back). A nil
/// `authEnforced` means unobservable, which is distinct from `AuthClass.none`
/// (a key created with no presence check).
public struct SecurityTierReport: Sendable, Equatable {
    public let achieved: SecurityLevel
    public let requested: TierPolicy?
    public let evidence: TierEvidence
    public let authEnforced: AuthClass?
    public let invalidated: Bool
    public let schemaVersion: Int

    public init(
        achieved: SecurityLevel,
        requested: TierPolicy?,
        evidence: TierEvidence,
        authEnforced: AuthClass?,
        invalidated: Bool,
        schemaVersion: Int = 1
    ) {
        self.achieved = achieved
        self.requested = requested
        self.evidence = evidence
        self.authEnforced = authEnforced
        self.invalidated = invalidated
        self.schemaVersion = schemaVersion
    }
}
