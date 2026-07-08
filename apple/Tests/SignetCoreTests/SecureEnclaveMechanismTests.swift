// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import Security
import Testing
@testable import SignetCore

/// Checks the Secure Enclave invariants the store's guarantees rest on
/// against the hardware Enclave with a transient key built
/// from the store's own access flags. A transient key is never added to the
/// keychain; it needs no entitlement and runs in an unsigned `swift test`
/// wherever an Enclave is reachable; a host or runner without one steps aside.
/// The persisted-key API is verified separately on a signed lane (VERIFICATION).
@Suite struct SecureEnclaveMechanismTests {
    /// A transient Secure Enclave P-256 key built with the store's access flags,
    /// or nil where no Enclave is reachable.
    func makeTransientSecureEnclaveKey() -> SecKey? {
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            SecureEnclaveKeyStore.accessFlags(for: .none),
            nil
        ) else { return nil }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrAccessControl as String: access,
            ],
        ]
        return SecKeyCreateRandomKey(attributes as CFDictionary, nil)
    }

    @Test func privateKeyNeverLeavesTheEnclave() throws {
        guard let privateKey = makeTransientSecureEnclaveKey() else { return }
        // The Secure Enclave private key has no external representation.
        #expect(SecKeyCopyExternalRepresentation(privateKey, nil) == nil)
        // Its public half exports as a 65-byte X9.63 uncompressed point.
        let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
        let raw = try #require(SecKeyCopyExternalRepresentation(publicKey, nil) as Data?)
        #expect(raw.count == 65)
        #expect(raw.first == 0x04)
    }

    @Test func signatureVerifiesAndConvertsToRawForm() throws {
        guard let privateKey = makeTransientSecureEnclaveKey() else { return }
        let digest = Data((0..<32).map { UInt8($0) })
        let der = try #require(
            SecKeyCreateSignature(
                privateKey, .ecdsaSignatureDigestX962SHA256, digest as CFData, nil
            ) as Data?
        )
        #expect(der.first == 0x30)  // DER SEQUENCE

        let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
        #expect(SecKeyVerifySignature(
            publicKey, .ecdsaSignatureDigestX962SHA256, digest as CFData, der as CFData, nil
        ))
        // The store's DER-to-raw parser yields the fixed 64-byte r || s form.
        let raw = try #require(SecureEnclaveKeyStore.derToRawRS(der))
        #expect(raw.count == 64)
    }
}
