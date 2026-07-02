// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure serialization test for the auth-gated sign gate. Proves a second
 * concurrent entrant is rejected while the first holds the gate; the biometric
 * prompt itself needs an emulator and is not exercised here.
 */
class AuthSignGateTest {
    @Test
    fun rejectsASecondEntrantUntilTheFirstExits() {
        val gate = AuthSignGate()
        assertTrue(gate.tryEnter()) // first acquires
        assertFalse(gate.tryEnter()) // second rejected while the first holds it
        assertFalse(gate.tryEnter()) // still rejected
        gate.exit()
        assertTrue(gate.tryEnter()) // released, the next sign can acquire
        gate.exit()
    }
}
