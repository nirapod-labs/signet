// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

/// The hardware backing a signing key, reported as the achieved level and never
/// assumed from the request. Closed set; see `conformance/security-level.json`.
public enum SecurityLevel: String, Sendable, Equatable, CaseIterable {
    case secureEnclave
    case strongBox
    case tee
    case tpm
    case software
}

/// How the achieved `SecurityLevel` was determined. Only `attested` is
/// cryptographic proof; every other value is an on-device self-report.
public enum TierEvidence: String, Sendable, Equatable, CaseIterable {
    case attested
    case keyInfoReadback
    case seTokenPresent
    case inferred
    case selfReportUnverified
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
/// `discreteSecure` covers Secure Enclave, StrongBox, and TPM, and outranks
/// `trustedEnvironment`.
public enum HardwareClass: String, Sendable, Equatable, CaseIterable {
    case discreteSecure
    case trustedEnvironment
}

/// Tier selection on `KeySpec`. Selection is by class, never a concrete
/// `SecurityLevel`; the achieved level is reported in `SecurityTierReport`.
public enum TierPolicy: Sendable, Equatable {
    /// The device's best hardware tier. Fails `unavailableTier` if no hardware
    /// is available; never returns software.
    case strongest
    /// A hard floor by class. Fails `unavailableTier` below the class.
    case atLeast(HardwareClass)
    /// Never fails on tier where a software keystore exists; may then return a
    /// weaker level with `meetsFloor == false` and honest evidence (the only
    /// policy that can return software). On a platform with no software backend
    /// (Apple), yields the Secure Enclave or fails `unavailableTier`.
    case bestEffort
}

extension HardwareClass {
    /// Rank in the partial order; lower is stronger.
    var rank: Int {
        switch self {
        case .discreteSecure: return 0
        case .trustedEnvironment: return 1
        }
    }
}

extension SecurityLevel {
    /// The partial-order class this level belongs to, or `nil` for `software`,
    /// which is below every hardware class.
    var hardwareClass: HardwareClass? {
        switch self {
        case .secureEnclave, .strongBox, .tpm: return .discreteSecure
        case .tee: return .trustedEnvironment
        case .software: return nil
        }
    }
}

/// One report shape everywhere. `achieved` is read back from the created key,
/// `meetsFloor` derives from the tier partial order, and `authEnforced` is
/// derived from the created access control.
public struct SecurityTierReport: Sendable, Equatable {
    public let achieved: SecurityLevel
    public let requested: TierPolicy
    public let meetsFloor: Bool
    public let evidence: TierEvidence
    public let authEnforced: AuthClass
    public let invalidated: Bool
    public let schemaVersion: Int

    public init(
        achieved: SecurityLevel,
        requested: TierPolicy,
        meetsFloor: Bool,
        evidence: TierEvidence,
        authEnforced: AuthClass,
        invalidated: Bool,
        schemaVersion: Int = 1
    ) {
        self.achieved = achieved
        self.requested = requested
        self.meetsFloor = meetsFloor
        self.evidence = evidence
        self.authEnforced = authEnforced
        self.invalidated = invalidated
        self.schemaVersion = schemaVersion
    }
}

extension TierPolicy {
    /// Whether `achieved` satisfies this policy's floor, per the partial order.
    func isMet(by achieved: SecurityLevel, platformStrongest: SecurityLevel) -> Bool {
        switch self {
        case .strongest:
            return achieved == platformStrongest
        case .atLeast(let floor):
            guard let achievedClass = achieved.hardwareClass else { return false }
            return achievedClass.rank <= floor.rank
        case .bestEffort:
            return achieved.hardwareClass == .discreteSecure
        }
    }
}
