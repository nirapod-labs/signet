// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import Security
import Testing
@testable import SignetCore

@Test func versionIsSet() {
    #expect(!Signet.version.isEmpty)
}

@Test func hardwareClassMapping() {
    // Secure Enclave is the only Apple level and maps to the top class.
    #expect(SecurityLevel.secureEnclave.hardwareClass == .discreteSecure)
}

@Test func creationFailureMappingIsHonest() {
    // A locked device is a transient platform failure, not a tier absence.
    #expect(SecureEnclaveKeyStore.mapCreationFailure(code: Int(errSecInteractionNotAllowed)) == .hardwareError)
    // A racing duplicate is reported as an existing alias, not a tier absence.
    #expect(SecureEnclaveKeyStore.mapCreationFailure(code: Int(errSecDuplicateItem)) == .keyAlreadyExists)
    // Any other creation failure fails closed with unavailableTier; never a software key.
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

@Test func derToRawRSConvertsAndPads() {
    // SEQUENCE { INTEGER 1, INTEGER 2 } -> r=1, s=2 in the low byte of each half.
    let small = SecureEnclaveKeyStore.derToRawRS(Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]))
    #expect(small?.count == 64)
    #expect(small?[31] == 0x01)
    #expect(small?[63] == 0x02)

    // High-bit components carry a DER 0x00 pad that must be stripped.
    let padded = SecureEnclaveKeyStore.derToRawRS(
        Data([0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x00, 0x81])
    )
    #expect(padded?.count == 64)
    #expect(padded?[31] == 0x80)
    #expect(padded?[63] == 0x81)

    // Malformed DER returns nil, never a wrong-length signature.
    #expect(SecureEnclaveKeyStore.derToRawRS(Data([0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])) == nil)
    #expect(SecureEnclaveKeyStore.derToRawRS(Data()) == nil)
}

@Test func signRejectsAWrongLengthDigest() {
    let store = SecureEnclaveKeyStore()
    // The digest guard fires before any keychain access; no Enclave is needed.
    #expect(throws: SignetError.invalidArgument) {
        _ = try store.sign(KeyHandle(alias: "signet.guard.unused"), digest: Data(count: 20))
    }
}

@Test func attestationResultDefaultsToAnEmptyChain() {
    let result = AttestationResult(format: .none)
    #expect(result.format == .none)
    #expect(result.chain.isEmpty)
    #expect(result.schemaVersion == 1)
}

@Test func securityTierReportSeparatesNilFromAuthClassNone() {
    // nil is unobservable at re-read; AuthClass.none is a key with no gate.
    let reread = SecurityTierReport(
        achieved: .secureEnclave, requested: nil,
        evidence: .seTokenPresent, authEnforced: nil, invalidated: false
    )
    #expect(reread.requested == nil)
    #expect(reread.authEnforced == nil)
    let created = SecurityTierReport(
        achieved: .secureEnclave, requested: TierPolicy.strongest,
        evidence: .seTokenPresent, authEnforced: AuthClass.none, invalidated: false
    )
    #expect(created.requested == TierPolicy.strongest)
    #expect(created.authEnforced == AuthClass.none)
    #expect(created.authEnforced != nil)
}
