// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation

/// A public key in one of the contract's wire formats. `rawX962` is the
/// uncompressed X9.63 point (`0x04 || X || Y`); `spki` is the DER
/// SubjectPublicKeyInfo wrapping that point.
public struct PublicKey: Sendable, Equatable {
    public enum Format: String, Sendable, Equatable, CaseIterable {
        case rawX962
        case spki
    }

    public let format: Format
    public let bytes: Data

    public init(format: Format, bytes: Data) {
        self.format = format
        self.bytes = bytes
    }
}
