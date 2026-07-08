// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet.kmp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Common assertions over the contract's shape and its tier partial order. These
 * run on every target; a source set that diverged from the contract fails here
 * before any platform code runs.
 */
class ContractTest {
    @Test
    fun securityLevelIsAClosedSetOfThree() {
        assertEquals(3, SecurityLevel.entries.size)
    }

    @Test
    fun tierEvidenceIsAClosedSetOfTwo() {
        assertEquals(2, TierEvidence.entries.size)
    }

    @Test
    fun authClassIsAClosedSetOfFour() {
        assertEquals(4, AuthClass.entries.size)
    }

    @Test
    fun errorTaxonomyIsThirteenWithPinnedSpelling() {
        assertEquals(13, SignetErrorCode.entries.size)
        assertTrue(SignetErrorCode.entries.any { it.name == "userCanceled" }, "spelling is userCanceled, one l")
        assertFalse(SignetErrorCode.entries.any { it.name == "userCancelled" })
    }

    @Test
    fun strongBoxIsDiscreteSecureAndNotBelowTee() {
        assertEquals(HardwareClass.discreteSecure, SecurityLevel.strongBox.hardwareClass)
        assertEquals(HardwareClass.trustedEnvironment, SecurityLevel.tee.hardwareClass)
        val discreteFloor = TierPolicy.AtLeast(HardwareClass.discreteSecure)
        assertTrue(discreteFloor.isMet(SecurityLevel.strongBox, platformStrongest = SecurityLevel.strongBox))
        assertFalse(discreteFloor.isMet(SecurityLevel.tee, platformStrongest = SecurityLevel.strongBox))
    }

    @Test
    fun strongestIsMetOnlyByThePlatformBest() {
        assertTrue(TierPolicy.Strongest.isMet(SecurityLevel.secureEnclave, platformStrongest = SecurityLevel.secureEnclave))
        assertFalse(TierPolicy.Strongest.isMet(SecurityLevel.tee, platformStrongest = SecurityLevel.strongBox))
    }

    @Test
    fun reportCarriesDefaultSchemaVersionAndTravelsWithItsHandle() {
        val report = SecurityTierReport(
            achieved = SecurityLevel.strongBox,
            requested = TierPolicy.Strongest,
            evidence = TierEvidence.keyInfoReadback,
            authEnforced = AuthClass.biometricOnly,
            invalidated = false,
        )
        assertEquals(1, report.schemaVersion)
        val result = KeyResult(KeyHandle("alias"), report)
        assertEquals("alias", result.handle.alias)
        assertEquals(report, result.report)
    }

    @Test
    fun signOptionsDefaultsToDer() {
        assertEquals(SignOptions.Encoding.der, SignOptions().encoding)
    }

    @Test
    fun accessControlNoneRequestsNoPresenceCheck() {
        assertEquals(AuthRequirement.none, AccessControlPolicy.None.authRequirement)
    }
}
