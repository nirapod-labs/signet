// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

/// The access-control policy requested for a key at generation. On Apple it is
/// applied as the key's `SecAccessControl`; the achieved `AuthClass` is reported
/// in `SecurityTierReport.authEnforced`.
public struct AccessControlPolicy: Sendable, Equatable {
    /// The presence check requested for the key.
    public enum AuthRequirement: String, Sendable, Equatable, CaseIterable {
        case none
        case biometricOnly
        case biometricOrDeviceCredential
    }

    /// The requested presence check.
    public let authRequirement: AuthRequirement
    /// Auth reuse window. `nil` or `0` means per-use auth; `> 0` means a time
    /// window. On Apple it is a sign-time value, not baked into the key; the
    /// current sign path does not apply it.
    public let authValiditySeconds: Int?
    /// Whether a biometric re-enrollment invalidates the key. `true` maps to
    /// `.biometryCurrentSet`, `false` to `.biometryAny`.
    public let invalidateOnBiometricEnrollment: Bool

    public init(
        authRequirement: AuthRequirement = .none,
        authValiditySeconds: Int? = nil,
        invalidateOnBiometricEnrollment: Bool = true
    ) {
        self.authRequirement = authRequirement
        self.authValiditySeconds = authValiditySeconds
        self.invalidateOnBiometricEnrollment = invalidateOnBiometricEnrollment
    }

    /// No presence check: usable without biometric or passcode auth.
    public static let none = AccessControlPolicy(authRequirement: .none)
}
