// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import Testing
@testable import SignetAppleCore

/// Secure Enclave lifecycle behavior. These assertions need a process that can
/// reach the Secure Enclave and the data-protection keychain: a signed app on
/// Enclave hardware, or the device lane. An unsigned `swift test` binary cannot;
/// each test probes first and steps aside where the Enclave is unreachable.
/// The device lane is the backstop for the stepped-aside path.
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
        #expect(report.authEnforced == .none)         // no auth gate in this surface
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
}
