// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet.kmp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import xyz.nirapod.signet.AttestationResult as CoreAttestationResult
import xyz.nirapod.signet.AuthClass as CoreAuthClass
import xyz.nirapod.signet.AuthRequirement as CoreAuthRequirement
import xyz.nirapod.signet.HardwareClass as CoreHardwareClass
import xyz.nirapod.signet.PublicKey as CorePublicKey
import xyz.nirapod.signet.SignOptions as CoreSignOptions
import xyz.nirapod.signet.SecurityLevel as CoreSecurityLevel
import xyz.nirapod.signet.SecurityTierReport as CoreSecurityTierReport
import xyz.nirapod.signet.SignetErrorCode as CoreSignetErrorCode
import xyz.nirapod.signet.TierEvidence as CoreTierEvidence
import xyz.nirapod.signet.TierPolicy as CoreTierPolicy

/**
 * Verifies the androidMain translation between the core's `xyz.nirapod.signet`
 * contract types and this module's `xyz.nirapod.signet.kmp` types. Runs on the
 * JVM host: the converters are pure and touch no key store. The by-name checks
 * fail if the two type sets ever drift apart.
 */
class ConvertersTest {
    @Test
    fun securityLevelMapsEveryEntryByName() {
        assertEquals(CoreSecurityLevel.entries.size, SecurityLevel.entries.size)
        CoreSecurityLevel.entries.forEach { assertEquals(it.name, it.toKmp().name) }
    }

    @Test
    fun tierEvidenceMapsEveryEntryByName() {
        assertEquals(CoreTierEvidence.entries.size, TierEvidence.entries.size)
        CoreTierEvidence.entries.forEach { assertEquals(it.name, it.toKmp().name) }
    }

    @Test
    fun authClassMapsEveryEntryByName() {
        assertEquals(CoreAuthClass.entries.size, AuthClass.entries.size)
        CoreAuthClass.entries.forEach { assertEquals(it.name, it.toKmp().name) }
    }

    @Test
    fun errorCodeMapsEveryEntryByName() {
        assertEquals(CoreSignetErrorCode.entries.size, SignetErrorCode.entries.size)
        CoreSignetErrorCode.entries.forEach { assertEquals(it.name, it.toKmp().name) }
    }

    @Test
    fun keySpecToCorePreservesFields() {
        val challenge = byteArrayOf(1, 2, 3)
        val core = KeySpec(
            alias = "k",
            tierPolicy = TierPolicy.AtLeast(HardwareClass.discreteSecure),
            accessControl = AccessControlPolicy(AuthRequirement.biometricOnly, 30, false),
            attestationChallenge = challenge,
        ).toCore()
        assertEquals("k", core.alias)
        val tierPolicy = assertIs<CoreTierPolicy.AtLeast>(core.tierPolicy)
        assertEquals(CoreHardwareClass.discreteSecure, tierPolicy.hardwareClass)
        assertEquals(CoreAuthRequirement.biometricOnly, core.accessControl.authRequirement)
        assertEquals(30, core.accessControl.authValiditySeconds)
        assertEquals(false, core.accessControl.invalidateOnBiometricEnrollment)
        assertTrue(challenge.contentEquals(core.attestationChallenge))
    }

    @Test
    fun tierReportToKmpPreservesFields() {
        val kmp = CoreSecurityTierReport(
            achieved = CoreSecurityLevel.strongBox,
            requested = CoreTierPolicy.Strongest,
            meetsFloor = true,
            evidence = CoreTierEvidence.keyInfoReadback,
            authEnforced = CoreAuthClass.biometricOnly,
            invalidated = false,
        ).toKmp()
        assertEquals(SecurityLevel.strongBox, kmp.achieved)
        assertEquals(TierPolicy.Strongest, kmp.requested)
        assertEquals(true, kmp.meetsFloor)
        assertEquals(TierEvidence.keyInfoReadback, kmp.evidence)
        assertEquals(AuthClass.biometricOnly, kmp.authEnforced)
        assertEquals(false, kmp.invalidated)
        assertEquals(1, kmp.schemaVersion)
    }

    @Test
    fun requestEnumsMapEveryEntryByName() {
        AuthRequirement.entries.forEach { assertEquals(it.name, it.toCore().name) }
        HardwareClass.entries.forEach { assertEquals(it.name, it.toCore().name) }
        SignOptions.Encoding.entries.forEach { assertEquals(it.name, it.toCore().name) }
        PublicKey.Format.entries.forEach { assertEquals(it.name, it.toCore().name) }
    }

    @Test
    fun responseFormatEnumsMapEveryEntryByName() {
        CorePublicKey.Format.entries.forEach { assertEquals(it.name, it.toKmp().name) }
        CoreAttestationResult.Format.entries.forEach { assertEquals(it.name, it.toKmp().name) }
        CoreHardwareClass.entries.forEach { assertEquals(it.name, it.toKmp().name) }
    }

    @Test
    fun structFieldsAreCarriedFaithfully() {
        val bytes = byteArrayOf(4, 5, 6)
        val pk = CorePublicKey(CorePublicKey.Format.spki, bytes).toKmp()
        assertEquals(PublicKey.Format.spki, pk.format)
        assertTrue(bytes.contentEquals(pk.bytes))

        val att = CoreAttestationResult(CoreAttestationResult.Format.none).toKmp()
        assertEquals(AttestationResult.Format.none, att.format)
        assertEquals(0, att.chain.size)
        assertEquals(1, att.schemaVersion)

        assertEquals(CoreSignOptions.Encoding.rawRS, SignOptions(SignOptions.Encoding.rawRS).toCore().encoding)
    }
}
