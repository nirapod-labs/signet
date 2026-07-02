// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import Security
import Testing
@testable import SignetAppleCore

/// Secure Enclave lifecycle behavior. These assertions need a process that can
/// reach the Secure Enclave and the data-protection keychain: a signed app on
/// Enclave hardware, or the device lane. An unsigned `swift test` binary cannot;
/// each test probes first and steps aside where the Enclave is unreachable. The
/// device lane is the backstop for the stepped-aside path.
@Suite struct KeyLifecycleTests {
    let store = SecureEnclaveKeyStore()

    /// True when this process can create and remove a Secure Enclave key here.
    func secureEnclaveReachable() -> Bool {
        let probe = "signet.probe.\(UUID().uuidString)"
        guard (try? store.generateKey(KeySpec(alias: probe))) != nil else { return false }
        try? store.delete(alias: probe)
        return true
    }

    @Test func generateProducesAnHonestSecureEnclaveReport() throws {
        guard secureEnclaveReachable() else { return }
        let alias = "signet.gen.\(UUID().uuidString)"
        defer { try? store.delete(alias: alias) }

        let (handle, report) = try store.generateKey(KeySpec(alias: alias))
        #expect(handle.alias == alias)
        #expect(report.achieved == .secureEnclave)
        #expect(report.evidence == .seTokenPresent)  // Apple SE is never attested
        #expect(report.meetsFloor)
        #expect(report.requested == TierPolicy.strongest)  // populated at creation
        #expect(report.authEnforced == AuthClass.none)     // no auth gate in this surface
        #expect(!report.invalidated)
        #expect(store.exists(alias: alias))
    }

    @Test func generateOnAnExistingAliasFails() throws {
        guard secureEnclaveReachable() else { return }
        let alias = "signet.dup.\(UUID().uuidString)"
        defer { try? store.delete(alias: alias) }

        _ = try store.generateKey(KeySpec(alias: alias))
        #expect(throws: SignetError.keyAlreadyExists) {
            _ = try store.generateKey(KeySpec(alias: alias))
        }
    }

    @Test func deleteRemovesTheKeyAndIsIdempotent() throws {
        guard secureEnclaveReachable() else { return }
        let alias = "signet.del.\(UUID().uuidString)"

        _ = try store.generateKey(KeySpec(alias: alias))
        #expect(store.exists(alias: alias))
        try store.delete(alias: alias)
        #expect(!store.exists(alias: alias))
        // A second delete on the now-absent alias must not throw.
        try store.delete(alias: alias)
    }

    @Test func gatedKeyReportsItsAuthClass() throws {
        guard secureEnclaveReachable() else { return }
        let alias = "signet.gated.\(UUID().uuidString)"
        defer { try? store.delete(alias: alias) }

        let policy = AccessControlPolicy(authRequirement: .biometricOrDeviceCredential)
        do {
            let (_, report) = try store.generateKey(KeySpec(alias: alias, accessControl: policy))
            #expect(report.authEnforced == AuthClass.biometricOrDeviceCredential)
        } catch let error as SignetError where error == .unavailableTier || error == .hardwareError {
            // A gated key needs an enrolled biometric or a device passcode to
            // bind to; where the environment has neither, creation fails with
            // one of these. Any other error fails the test. The device lane
            // configures auth and verifies the success path.
        }
    }

    @Test func privateKeyIsNotExportable() throws {
        guard secureEnclaveReachable() else { return }
        let alias = "signet.export.\(UUID().uuidString)"
        defer { try? store.delete(alias: alias) }
        _ = try store.generateKey(KeySpec(alias: alias))

        // The Secure Enclave private key has no external representation.
        let privateKey = try store.fetchKey(alias: alias)
        #expect(SecKeyCopyExternalRepresentation(privateKey, nil) == nil)
    }

    @Test func getPublicKeyReturnsRawAndSpki() throws {
        guard secureEnclaveReachable() else { return }
        let alias = "signet.pub.\(UUID().uuidString)"
        defer { try? store.delete(alias: alias) }
        let (handle, _) = try store.generateKey(KeySpec(alias: alias))

        let raw = try store.getPublicKey(handle)
        #expect(raw.format == .rawX962)
        #expect(raw.bytes.count == 65)
        #expect(raw.bytes.first == 0x04)  // uncompressed point

        let spki = try store.getPublicKey(handle, format: .spki)
        #expect(spki.format == .spki)
        #expect(spki.bytes.count == 91)
        #expect(spki.bytes.suffix(65) == raw.bytes)  // wraps the same point
    }

    @Test func signProducesAVerifiableSignature() throws {
        guard secureEnclaveReachable() else { return }
        let alias = "signet.sign.\(UUID().uuidString)"
        defer { try? store.delete(alias: alias) }
        let (handle, _) = try store.generateKey(KeySpec(alias: alias))
        let digest = Data((0..<32).map { UInt8($0) })

        let der = try store.sign(handle, digest: digest)
        #expect(der.first == 0x30)  // DER SEQUENCE

        // The signature verifies against the key's public half.
        let privateKey = try store.fetchKey(alias: alias)
        let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
        #expect(SecKeyVerifySignature(
            publicKey,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            der as CFData,
            nil
        ))

        let raw = try store.sign(handle, digest: digest, options: SignOptions(encoding: .rawRS))
        #expect(raw.count == 64)
    }

    @Test func getSecurityTierRereadsObservableState() throws {
        guard secureEnclaveReachable() else { return }
        let alias = "signet.tier.\(UUID().uuidString)"
        defer { try? store.delete(alias: alias) }
        let (handle, _) = try store.generateKey(KeySpec(alias: alias))

        let report = try store.getSecurityTier(handle)
        #expect(report.achieved == .secureEnclave)
        #expect(report.evidence == .seTokenPresent)
        #expect(report.meetsFloor)
        #expect(!report.invalidated)
        // A re-read cannot recover the creation-time fields on Apple.
        #expect(report.requested == nil)
        #expect(report.authEnforced == nil)
    }

    @Test func getAttestationReturnsNoneForASecureEnclaveKey() throws {
        guard secureEnclaveReachable() else { return }
        let alias = "signet.attest.\(UUID().uuidString)"
        defer { try? store.delete(alias: alias) }
        let (handle, _) = try store.generateKey(KeySpec(alias: alias))

        let result = try store.getAttestation(handle)
        #expect(result.format == .none)
        #expect(result.chain.isEmpty)
    }

    @Test func tierAndAttestationThrowNotFoundForAMissingKey() throws {
        guard secureEnclaveReachable() else { return }
        let missing = KeyHandle(alias: "signet.missing.\(UUID().uuidString)")
        #expect(throws: SignetError.notFound) { _ = try store.getSecurityTier(missing) }
        #expect(throws: SignetError.notFound) { _ = try store.getAttestation(missing) }
    }
}
