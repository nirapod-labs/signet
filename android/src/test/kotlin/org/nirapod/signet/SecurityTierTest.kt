// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet

import android.security.keystore.KeyProperties
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
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
    }

    @Test
    fun strongestRequiresThePlatformBestTier() {
        // A StrongBox device that fell back to the TEE does not meet strongest.
        assertFalse(TierPolicy.Strongest.isMet(SecurityLevel.tee, SecurityLevel.strongBox))
        // Where the device's best is the TEE, a TEE key meets strongest.
        assertTrue(TierPolicy.Strongest.isMet(SecurityLevel.tee, SecurityLevel.tee))
    }

    @Test
    fun atLeastTracksThePartialOrder() {
        val strongBox = SecurityLevel.strongBox
        // A trustedEnvironment floor is met by a tee level, not a discreteSecure floor.
        assertTrue(TierPolicy.AtLeast(HardwareClass.trustedEnvironment).isMet(SecurityLevel.tee, strongBox))
        assertFalse(TierPolicy.AtLeast(HardwareClass.discreteSecure).isMet(SecurityLevel.tee, strongBox))
    }

    @Test
    fun hardwareClassMapping() {
        // The mapping is total over the hardware-only level set.
        assertEquals(HardwareClass.discreteSecure, SecurityLevel.strongBox.hardwareClass)
        assertEquals(HardwareClass.trustedEnvironment, SecurityLevel.tee.hardwareClass)
    }

    @Test
    fun securityLevelFromCodeMapsHardwareLevels() {
        assertEquals(
            SecurityLevel.strongBox,
            AndroidKeyStoreSigner.securityLevelFromCode(KeyProperties.SECURITY_LEVEL_STRONGBOX),
        )
        assertEquals(
            SecurityLevel.tee,
            AndroidKeyStoreSigner.securityLevelFromCode(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT),
        )
    }

    @Test
    fun securityLevelFromCodeTreatsUnknownSecureAsTee() {
        // UNKNOWN_SECURE is secure hardware of an unnamed class; it maps to the
        // weakest secure tier, never fails closed and never over-claims StrongBox.
        assertEquals(
            SecurityLevel.tee,
            AndroidKeyStoreSigner.securityLevelFromCode(KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE),
        )
    }

    @Test
    fun securityLevelFromCodeFailsClosedOnSoftware() {
        // A software-backed level never returns a tier; it fails closed.
        val error = assertThrows(SignetException::class.java) {
            AndroidKeyStoreSigner.securityLevelFromCode(KeyProperties.SECURITY_LEVEL_SOFTWARE)
        }
        assertEquals(SignetErrorCode.unavailableTier, error.code)
    }

    @Test
    fun securityLevelFromCodeFailsClosedOnUnknown() {
        // An unknown level is unexpected hardware state, not a tier.
        val error = assertThrows(SignetException::class.java) {
            AndroidKeyStoreSigner.securityLevelFromCode(KeyProperties.SECURITY_LEVEL_UNKNOWN)
        }
        assertEquals(SignetErrorCode.hardwareError, error.code)
    }

    @Test
    fun reportSeparatesNullFromAuthClassNone() {
        // null is unobservable at re-read; AuthClass.none is a key with no gate.
        val reread = SecurityTierReport(
            achieved = SecurityLevel.strongBox,
            requested = null,
            evidence = TierEvidence.keyInfoReadback,
            authEnforced = null,
            invalidated = false,
        )
        assertNull(reread.requested)
        assertNull(reread.authEnforced)

        val created = SecurityTierReport(
            achieved = SecurityLevel.strongBox,
            requested = TierPolicy.Strongest,
            evidence = TierEvidence.keyInfoReadback,
            authEnforced = AuthClass.none,
            invalidated = false,
        )
        assertEquals(TierPolicy.Strongest, created.requested)
        assertEquals(AuthClass.none, created.authEnforced)
        assertNotNull(created.authEnforced)
    }
}
