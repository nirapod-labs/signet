// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Security
import Testing
@testable import SignetAppleCore

@Test func versionIsSet() {
    #expect(!Signet.version.isEmpty)
    #expect(Signet.platformTag() == "apple")
}

@Test func secureEnclaveMeetsEveryPolicyFloor() {
    // Secure Enclave is discreteSecure (top class) and Apple's strongest level;
    // every policy is met on the success path.
    let se = SecurityLevel.secureEnclave
    #expect(TierPolicy.strongest.isMet(by: se, platformStrongest: se))
    #expect(TierPolicy.atLeast(.discreteSecure).isMet(by: se, platformStrongest: se))
    #expect(TierPolicy.atLeast(.trustedEnvironment).isMet(by: se, platformStrongest: se))
    #expect(TierPolicy.bestEffort.isMet(by: se, platformStrongest: se))
}

@Test func meetsFloorTracksThePartialOrder() {
    let se = SecurityLevel.secureEnclave
    // A trustedEnvironment floor is met by a discreteSecure level, not the reverse.
    #expect(TierPolicy.atLeast(.trustedEnvironment).isMet(by: .tee, platformStrongest: se))
    #expect(!TierPolicy.atLeast(.discreteSecure).isMet(by: .tee, platformStrongest: se))
    // strongest is met only by the platform's strongest level.
    #expect(!TierPolicy.strongest.isMet(by: .tee, platformStrongest: se))
    // bestEffort flags a below-class result: false for tee and software.
    #expect(!TierPolicy.bestEffort.isMet(by: .tee, platformStrongest: se))
    #expect(!TierPolicy.bestEffort.isMet(by: .software, platformStrongest: se))
}

@Test func hardwareClassMapping() {
    #expect(SecurityLevel.software.hardwareClass == nil)
    #expect(SecurityLevel.tee.hardwareClass == .trustedEnvironment)
    #expect(SecurityLevel.secureEnclave.hardwareClass == .discreteSecure)
    #expect(SecurityLevel.strongBox.hardwareClass == .discreteSecure)
    #expect(SecurityLevel.tpm.hardwareClass == .discreteSecure)
}

@Test func creationFailureMappingIsHonest() {
    // A locked device is a transient platform failure, not a tier absence.
    #expect(SecureEnclaveKeyStore.mapCreationFailure(code: Int(errSecInteractionNotAllowed)) == .hardwareError)
    // A racing duplicate is reported as an existing alias, not a tier absence.
    #expect(SecureEnclaveKeyStore.mapCreationFailure(code: Int(errSecDuplicateItem)) == .keyAlreadyExists)
    // Any other creation failure fails unavailableTier; never software.
    #expect(SecureEnclaveKeyStore.mapCreationFailure(code: Int(errSecParam)) == .unavailableTier)
    #expect(SecureEnclaveKeyStore.mapCreationFailure(code: 0) == .unavailableTier)
}
