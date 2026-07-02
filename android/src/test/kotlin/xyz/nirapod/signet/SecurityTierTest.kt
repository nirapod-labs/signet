// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

import android.security.keystore.KeyProperties
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure tier-logic tests. These reference only inlined `KeyProperties` constants
 * and run as JVM unit tests with no Keystore. The Keystore surface itself needs
 * an emulator and is not exercised here.
 */
class SecurityTierTest {
    @Test
    fun strongBoxMeetsEveryPolicyFloor() {
        val strongBox = SecurityLevel.strongBox
        assertTrue(TierPolicy.Strongest.isMet(strongBox, strongBox))
        assertTrue(TierPolicy.AtLeast(HardwareClass.discreteSecure).isMet(strongBox, strongBox))
        assertTrue(TierPolicy.AtLeast(HardwareClass.trustedEnvironment).isMet(strongBox, strongBox))
        assertTrue(TierPolicy.BestEffort.isMet(strongBox, strongBox))
    }

    @Test
    fun strongestRequiresThePlatformBestTier() {
        // A StrongBox device that fell back to the TEE does not meet strongest.
        assertFalse(TierPolicy.Strongest.isMet(SecurityLevel.tee, SecurityLevel.strongBox))
        // Where the device's best is the TEE, a TEE key meets strongest.
        assertTrue(TierPolicy.Strongest.isMet(SecurityLevel.tee, SecurityLevel.tee))
        // strongest never counts a software key as met.
        assertFalse(TierPolicy.Strongest.isMet(SecurityLevel.software, SecurityLevel.tee))
    }

    @Test
    fun meetsFloorTracksThePartialOrder() {
        val strongBox = SecurityLevel.strongBox
        // A trustedEnvironment floor is met by a tee level, not a discreteSecure floor.
        assertTrue(TierPolicy.AtLeast(HardwareClass.trustedEnvironment).isMet(SecurityLevel.tee, strongBox))
        assertFalse(TierPolicy.AtLeast(HardwareClass.discreteSecure).isMet(SecurityLevel.tee, strongBox))
        // bestEffort flags a below-class result: false for tee and software.
        assertFalse(TierPolicy.BestEffort.isMet(SecurityLevel.tee, strongBox))
        assertFalse(TierPolicy.BestEffort.isMet(SecurityLevel.software, strongBox))
    }

    @Test
    fun hardwareClassMapping() {
        assertNull(SecurityLevel.software.hardwareClass)
        assertEquals(HardwareClass.trustedEnvironment, SecurityLevel.tee.hardwareClass)
        assertEquals(HardwareClass.discreteSecure, SecurityLevel.strongBox.hardwareClass)
        assertEquals(HardwareClass.discreteSecure, SecurityLevel.secureEnclave.hardwareClass)
        assertEquals(HardwareClass.discreteSecure, SecurityLevel.tpm.hardwareClass)
    }

    @Test
    fun securityLevelFromCodeMapsKeystoreLevels() {
        assertEquals(
            SecurityLevel.strongBox,
            AndroidKeyStoreSigner.securityLevelFromCode(KeyProperties.SECURITY_LEVEL_STRONGBOX),
        )
        assertEquals(
            SecurityLevel.tee,
            AndroidKeyStoreSigner.securityLevelFromCode(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT),
        )
        assertEquals(
            SecurityLevel.software,
            AndroidKeyStoreSigner.securityLevelFromCode(KeyProperties.SECURITY_LEVEL_SOFTWARE),
        )
        // An unknown level is never inflated to a hardware tier.
        assertEquals(
            SecurityLevel.software,
            AndroidKeyStoreSigner.securityLevelFromCode(KeyProperties.SECURITY_LEVEL_UNKNOWN),
        )
    }

    @Test
    fun reportSeparatesNullFromAuthClassNone() {
        // null is unobservable at re-read; AuthClass.none is a key with no gate.
        val reread = SecurityTierReport(
            achieved = SecurityLevel.strongBox,
            requested = null,
            meetsFloor = true,
            evidence = TierEvidence.keyInfoReadback,
            authEnforced = null,
            invalidated = false,
        )
        assertNull(reread.requested)
        assertNull(reread.authEnforced)

        val created = SecurityTierReport(
            achieved = SecurityLevel.strongBox,
            requested = TierPolicy.Strongest,
            meetsFloor = true,
            evidence = TierEvidence.keyInfoReadback,
            authEnforced = AuthClass.none,
            invalidated = false,
        )
        assertEquals(TierPolicy.Strongest, created.requested)
        assertEquals(AuthClass.none, created.authEnforced)
        assertNotNull(created.authEnforced)
    }
}
