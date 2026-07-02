// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation

/// The result of `getAttestation`. On Apple the Secure Enclave has no per-key
/// hardware attestation; `format` is always `none` and `chain` is empty. A
/// certificate chain (`androidKeyChain`) is produced only where the platform
/// supports key attestation. The attestation challenge is bound at key
/// generation, never here.
public struct AttestationResult: Sendable, Equatable {
    /// The attestation wire format.
    public enum Format: String, Sendable, Equatable, CaseIterable {
        /// A hardware key-attestation certificate chain.
        case androidKeyChain
        /// No attestation is available for this key or platform.
        case none
    }

    public let format: Format
    /// The certificate chain, one DER-encoded certificate per element. Empty
    /// when `format` is `none`.
    public let chain: [Data]
    public let schemaVersion: Int

    public init(format: Format, chain: [Data] = [], schemaVersion: Int = 1) {
        self.format = format
        self.chain = chain
        self.schemaVersion = schemaVersion
    }
}
