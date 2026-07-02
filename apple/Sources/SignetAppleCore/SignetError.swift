// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

/// The one closed error set every Signet core and binding raises.
///
/// Names and spelling (`userCanceled`) are fixed by the cross-language contract
/// in `conformance/errors.json`. A binding maps a structured case to its
/// idiomatic form without interpreting platform exceptions.
public enum SignetError: Error, Equatable, Sendable {
    /// The requested hardware tier is not available and no downgrade applies.
    case unavailableTier
    /// The user dismissed the authentication prompt.
    case userCanceled
    /// The key was invalidated, for example by biometric re-enrollment.
    case keyInvalidated
    /// Authentication was attempted and failed.
    case authFailed
    /// An auth-gated operation was invoked with no host UI context available.
    case authContextRequired
    /// No key exists for the given alias.
    case notFound
    /// A key already exists for the alias; generation does not overwrite.
    case keyAlreadyExists
    /// An existing key does not match the requested tier.
    case tierMismatchOnExisting
    /// Attestation is not supported for this key or platform.
    case attestationUnsupported
    /// A platform key-store or hardware operation failed.
    case hardwareError
    /// The operation is not supported on this platform.
    case unsupportedPlatform
    /// The caller violated a locally-checkable precondition, for example a
    /// digest that is not exactly 32 bytes. Rejected before any platform call;
    /// never conflated with `hardwareError`.
    case invalidArgument
    /// An auth-gated operation was issued while another's biometric prompt was
    /// still outstanding; the concurrent request is rejected, not queued.
    case authInProgress
}
