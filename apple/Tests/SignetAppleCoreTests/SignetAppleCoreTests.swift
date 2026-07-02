// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
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

@Test func accessFlagsMapEachPolicy() {
    let bioOnly = AccessControlPolicy(authRequirement: .biometricOnly)
    let bioOnlyAny = AccessControlPolicy(
        authRequirement: .biometricOnly,
        invalidateOnBiometricEnrollment: false
    )
    let bioOrPasscode = AccessControlPolicy(authRequirement: .biometricOrDeviceCredential)
    // No presence check: private-key usage only.
    #expect(SecureEnclaveKeyStore.accessFlags(for: .none) == .privateKeyUsage)
    // Biometric only, default: the currently-enrolled set (invalidated on re-enrollment).
    #expect(SecureEnclaveKeyStore.accessFlags(for: bioOnly) == [.privateKeyUsage, .biometryCurrentSet])
    // Biometric only, surviving re-enrollment: any enrolled biometry.
    #expect(SecureEnclaveKeyStore.accessFlags(for: bioOnlyAny) == [.privateKeyUsage, .biometryAny])
    // Biometric or passcode: biometry OR the device passcode.
    #expect(
        SecureEnclaveKeyStore.accessFlags(for: bioOrPasscode)
            == [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]
    )
}

@Test func authClassTracksTheRequirement() {
    let bio = AccessControlPolicy(authRequirement: .biometricOnly)
    let bioOrPasscode = AccessControlPolicy(authRequirement: .biometricOrDeviceCredential)
    #expect(SecureEnclaveKeyStore.authClass(for: .none) == .none)
    #expect(SecureEnclaveKeyStore.authClass(for: bio) == .biometricOnly)
    #expect(SecureEnclaveKeyStore.authClass(for: bioOrPasscode) == .biometricOrDeviceCredential)
}

@Test func spkiWrapsTheP256Point() {
    let point = Data([0x04] + [UInt8](repeating: 0xAB, count: 64))
    let spki = SecureEnclaveKeyStore.spki(fromRawX962: point)
    let header: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    ]
    #expect(spki.count == 91)
    #expect(Array(spki.prefix(26)) == header)
    #expect(spki.suffix(65) == point)
}
