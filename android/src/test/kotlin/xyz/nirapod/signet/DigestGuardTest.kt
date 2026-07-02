// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/**
 * Pure guard tests for the sign surface's caller-checkable preconditions. The
 * digest length is validated before any key access and needs no Keystore.
 */
class DigestGuardTest {
    @Test
    fun acceptsExactly32Bytes() {
        AndroidKeyStoreSigner.requireDigest32(ByteArray(32)) // no throw
    }

    @Test
    fun rejectsWrongLengthWithInvalidArgument() {
        for (size in intArrayOf(0, 1, 31, 33, 64)) {
            try {
                AndroidKeyStoreSigner.requireDigest32(ByteArray(size))
                fail("expected invalidArgument for a $size-byte digest")
            } catch (error: SignetException) {
                assertEquals(SignetErrorCode.invalidArgument, error.code)
            }
        }
    }

    @Test
    fun signOptionsDefaultsToDer() {
        assertEquals(SignOptions.Encoding.der, SignOptions().encoding)
    }
}
