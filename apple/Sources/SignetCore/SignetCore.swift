// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

/// Signet Apple core entry point.
///
/// The module exposes a hardware-backed P-256 surface over the Secure Enclave
/// through `SecureEnclaveKeyStore`. There is no export path for private keys.
public enum Signet {
    /// Library version, aligned with the repository VERSION file.
    public static let version = "0.1.0-dev"
}
