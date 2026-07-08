// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

/// Options for `sign`. `normalizeLowS` is part of the cross-language contract
/// but is not exposed here yet; it lands with the shared low-S implementation
/// once its byte-exact conformance vector is green across every binding.
public struct SignOptions: Sendable, Equatable {
    /// The signature wire format.
    public enum Encoding: String, Sendable, Equatable, CaseIterable {
        /// X9.62 DER `SEQUENCE { INTEGER r, INTEGER s }` (the native SE output).
        case der
        /// Fixed 64-byte `r || s`, each a 32-byte big-endian integer.
        case rawRS = "raw-r-s"
    }

    public let encoding: Encoding

    public init(encoding: Encoding = .der) {
        self.encoding = encoding
    }
}
