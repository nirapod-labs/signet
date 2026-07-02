// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import Security

/// Secure Enclave-backed P-256 key store for iOS and macOS.
///
/// Keys are created non-exportable in the Secure Enclave. There is no export
/// path: the outputs are a handle, a public key (separate surface), a signature,
/// and attestation, never private-key bytes. Secure Enclave creation failure
/// raises `unavailableTier`; the store never falls back to software.
public struct SecureEnclaveKeyStore: Sendable {
    /// Namespaces the application tag so Signet keys do not collide with other
    /// keychain items in the app's access group.
    private static let tagPrefix = "nirapod.signet."

    public init() {}

    /// Generates a non-exportable P-256 key in the Secure Enclave.
    ///
    /// - Returns: the key handle and a tier report read from what was created
    ///   (`achieved`, `evidence`, `meetsFloor`).
    /// - Throws: `keyAlreadyExists` if the alias is taken; `unavailableTier` if
    ///   the Secure Enclave cannot create the key; `hardwareError` if the
    ///   access-control object cannot be built.
    public func generateKey(_ spec: KeySpec) throws -> (KeyHandle, SecurityTierReport) {
        guard !exists(alias: spec.alias) else {
            throw SignetError.keyAlreadyExists
        }

        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            nil
        ) else {
            throw SignetError.hardwareError
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag(for: spec.alias),
                kSecAttrAccessControl as String: access,
                kSecUseDataProtectionKeychain as String: true,
            ],
        ]

        var cfError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &cfError) != nil else {
            // Never fall back to software. Map the failure cause honestly.
            let code = (cfError?.takeRetainedValue()).map { CFErrorGetCode($0) } ?? 0
            throw Self.mapCreationFailure(code: code)
        }

        let report = SecurityTierReport(
            achieved: .secureEnclave,
            requested: spec.tierPolicy,
            meetsFloor: spec.tierPolicy.isMet(
                by: .secureEnclave,
                platformStrongest: .secureEnclave
            ),
            evidence: .seTokenPresent,
            authEnforced: .none,
            invalidated: false
        )
        return (KeyHandle(alias: spec.alias), report)
    }

    /// Reports whether a key exists for the alias without materializing a handle.
    public func exists(alias: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag(for: alias),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: false,
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    /// Deletes the key for the alias. Idempotent: a missing key is a success.
    ///
    /// - Throws: `hardwareError` if the key store rejects the delete for any
    ///   reason other than the key being absent.
    public func delete(alias: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag(for: alias),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SignetError.hardwareError
        }
    }

    /// Maps a `SecKeyCreateRandomKey` failure code to the closed error set.
    /// `errSecInteractionNotAllowed` (locked device) is `hardwareError`, a
    /// transient platform failure, not a tier absence. `errSecDuplicateItem` is
    /// `keyAlreadyExists`. Every other code is `unavailableTier`; never software.
    static func mapCreationFailure(code: Int) -> SignetError {
        switch code {
        case Int(errSecInteractionNotAllowed):
            return .hardwareError
        case Int(errSecDuplicateItem):
            return .keyAlreadyExists
        default:
            return .unavailableTier
        }
    }

    /// Application tag for an alias: the library namespace prefix plus the alias.
    private func tag(for alias: String) -> Data {
        Data((Self.tagPrefix + alias).utf8)
    }
}
