// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

@file:OptIn(ExperimentalForeignApi::class)

package org.nirapod.signet.kmp

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import platform.CoreFoundation.CFRelease
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCopyPublicKey
import platform.Security.SecKeyCreateRandomKey
import platform.Security.errSecDuplicateItem
import platform.Security.errSecInteractionNotAllowed
import platform.Security.kSecAccessControlBiometryAny
import platform.Security.kSecAccessControlBiometryCurrentSet
import platform.Security.kSecAccessControlDevicePasscode
import platform.Security.kSecAccessControlOr
import platform.Security.kSecAccessControlPrivateKeyUsage
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Foundation.NSError
import platform.LocalAuthentication.LAErrorAuthenticationFailed
import platform.LocalAuthentication.LAErrorBiometryNotEnrolled
import platform.LocalAuthentication.LAErrorDomain
import platform.LocalAuthentication.LAErrorUserCancel
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Verifies the appleMain Secure Enclave binding. The pure codec and policy mapping
 * run with no keychain access. One transient host-key round-trip proves the
 * Security.framework binding links and signs; the real Secure Enclave path
 * (persistent keys, `secureEnclave` tier, attestation) is device-farm-gated and
 * tracked in `kmp/VERIFICATION.md`. Runs on `macosArm64Test` (native host, not a
 * simulator).
 */
class SecureEnclaveTest {

    @Test
    fun derToRawRsMapsCanonicalSignature() {
        val r = ByteArray(32) { 0x11 }
        val s = ByteArray(32) { 0x22 }
        val der = byteArrayOf(0x30, 0x44, 0x02, 0x20) + r + byteArrayOf(0x02, 0x20) + s
        val raw = derToRawRS(der) ?: fail("canonical DER should parse")
        assertEquals(64, raw.size)
        assertContentEquals(r, raw.copyOfRange(0, 32))
        assertContentEquals(s, raw.copyOfRange(32, 64))
    }

    @Test
    fun derToRawRsStripsPositivePadding() {
        val rRaw = ByteArray(32) { if (it == 0) 0x80.toByte() else 0x11 }
        val s = ByteArray(32) { 0x22 }
        // r is encoded with a leading 0x00 because its high bit is set.
        val der = byteArrayOf(0x30, 0x45, 0x02, 0x21, 0x00) + rRaw + byteArrayOf(0x02, 0x20) + s
        val raw = derToRawRS(der) ?: fail("padded DER should parse")
        assertEquals(64, raw.size)
        assertContentEquals(rRaw, raw.copyOfRange(0, 32))
    }

    @Test
    fun derToRawRsLeftPadsShortComponents() {
        val s = ByteArray(32) { 0x22 }
        val der = byteArrayOf(0x30, 0x25, 0x02, 0x01, 0x05, 0x02, 0x20) + s
        val raw = derToRawRS(der) ?: fail("short-component DER should parse")
        assertEquals(64, raw.size)
        assertEquals(0x05.toByte(), raw[31])
        assertTrue(raw.copyOfRange(0, 31).all { it == 0x00.toByte() })
    }

    @Test
    fun derToRawRsRejectsMalformed() {
        assertNull(derToRawRS(ByteArray(0)))
        assertNull(derToRawRS(byteArrayOf(0x31, 0x44)), "wrong SEQUENCE tag")
        assertNull(derToRawRS(byteArrayOf(0x30, 0x44, 0x02, 0x20, 0x01, 0x02)), "truncated body")
        // A 33-byte component that is not positive-padding exceeds 32 after parse.
        val big = ByteArray(33) { 0x11 }
        val der = byteArrayOf(0x30, 0x25, 0x02, 0x21) + big
        assertNull(derToRawRS(der), "over-32 component")
    }

    @Test
    fun spkiPrependsFixedHeader() {
        val point = ByteArray(65) { if (it == 0) 0x04 else 0x07 }
        val spki = spkiFromRawX962(point)
        assertEquals(91, spki.size)
        assertEquals(0x30.toByte(), spki[0])
        assertEquals(0x59.toByte(), spki[1])
        assertContentEquals(point, spki.copyOfRange(26, 91))
    }

    @Test
    fun accessFlagsMapEachPolicy() {
        assertEquals(kSecAccessControlPrivateKeyUsage, accessFlags(AccessControlPolicy.None))
        assertEquals(
            kSecAccessControlPrivateKeyUsage or kSecAccessControlBiometryCurrentSet,
            accessFlags(AccessControlPolicy(AuthRequirement.biometricOnly, invalidateOnBiometricEnrollment = true)),
        )
        assertEquals(
            kSecAccessControlPrivateKeyUsage or kSecAccessControlBiometryAny,
            accessFlags(AccessControlPolicy(AuthRequirement.biometricOnly, invalidateOnBiometricEnrollment = false)),
        )
        assertEquals(
            kSecAccessControlPrivateKeyUsage or kSecAccessControlBiometryCurrentSet or
                kSecAccessControlOr or kSecAccessControlDevicePasscode,
            accessFlags(AccessControlPolicy(AuthRequirement.biometricOrDeviceCredential)),
        )
    }

    @Test
    fun authClassMapsEachPolicy() {
        assertEquals(AuthClass.none, authClass(AccessControlPolicy.None))
        assertEquals(AuthClass.biometricOnly, authClass(AccessControlPolicy(AuthRequirement.biometricOnly)))
        assertEquals(
            AuthClass.biometricOrDeviceCredential,
            authClass(AccessControlPolicy(AuthRequirement.biometricOrDeviceCredential)),
        )
    }

    @Test
    fun mapCreationFailureMapsCodes() {
        assertEquals(SignetErrorCode.hardwareError, mapCreationFailure(errSecInteractionNotAllowed.convert<Long>()))
        assertEquals(SignetErrorCode.keyAlreadyExists, mapCreationFailure(errSecDuplicateItem.convert<Long>()))
        assertEquals(SignetErrorCode.unavailableTier, mapCreationFailure(-999999L))
    }

    @Test
    fun tagIsNamespaced() {
        assertEquals("nirapod.signet.wallet", tag("wallet").decodeToString())
    }

    @Test
    fun transientKeySignRoundTripProvesBinding() = memScoped {
        val attributes = cfDictionaryOf(
            kSecAttrKeyType to kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits to cfNumber(256),
        )
        val key = SecKeyCreateRandomKey(attributes, null) ?: fail("transient P-256 keygen should succeed on the host")
        defer { CFRelease(key) }

        val publicKey = SecKeyCopyPublicKey(key) ?: fail("public key copy should succeed")
        defer { CFRelease(publicKey) }
        val rawRef = SecKeyCopyExternalRepresentation(publicKey, null) ?: fail("external representation should succeed")
        defer { CFRelease(rawRef) }
        val raw = cfDataToByteArray(rawRef)
        assertEquals(65, raw.size)
        assertEquals(0x04.toByte(), raw[0])

        val digest = ByteArray(32) { (it + 1).toByte() }
        val der = signWithKey(key, digest, SignOptions(SignOptions.Encoding.der))
        assertEquals(0x30.toByte(), der[0])
        val rawRs = signWithKey(key, digest, SignOptions(SignOptions.Encoding.rawRS))
        assertEquals(64, rawRs.size)
    }

    @Test
    fun cfDataHandlesEmptyInput() = memScoped {
        assertEquals(0, cfDataToByteArray(cfData(ByteArray(0))).size)
    }

    @Test
    fun gatedReasonAppendsSubtitle() {
        assertEquals("Sign in", gatedReason(AuthContext("Sign in", AuthRequirement.biometricOnly)))
        assertEquals(
            "Sign in\nApprove the transfer",
            gatedReason(AuthContext("Sign in", AuthRequirement.biometricOnly, "Approve the transfer")),
        )
    }

    @Test
    fun signGateRejectsConcurrentEntry() {
        val gate = SignGate()
        assertTrue(gate.tryEnter())
        assertFalse(gate.tryEnter())
        gate.exit()
        assertTrue(gate.tryEnter())
        gate.exit()
    }

    @Test
    fun mapGatedSignFailureMapsAuthCodes() {
        assertEquals(
            SignetErrorCode.userCanceled,
            mapGatedSignFailure(NSError(domain = LAErrorDomain, code = LAErrorUserCancel, userInfo = null)),
        )
        assertEquals(
            SignetErrorCode.authFailed,
            mapGatedSignFailure(NSError(domain = LAErrorDomain, code = LAErrorAuthenticationFailed, userInfo = null)),
        )
        assertEquals(
            SignetErrorCode.authContextRequired,
            mapGatedSignFailure(NSError(domain = LAErrorDomain, code = LAErrorBiometryNotEnrolled, userInfo = null)),
        )
        assertEquals(SignetErrorCode.hardwareError, mapGatedSignFailure(null))
    }
}
