// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

/// Signet Apple core entry point.
///
/// Scaffold: the module builds with no Secure Enclave access and no export
/// symbol. The hardware-backed P-256 surface over `SecKey` and the Secure
/// Enclave is added with the key code and proven in tests.
public enum Signet {
    /// Library version, aligned with the repository VERSION file.
    public static let version = "0.1.0-dev"

    /// Returns the platform tag of this core build.
    public static func platformTag() -> String {
        return "apple"
    }
}
