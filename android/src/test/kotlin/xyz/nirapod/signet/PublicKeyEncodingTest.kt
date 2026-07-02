// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

import org.junit.Assert.assertEquals
import org.junit.Test
import java.math.BigInteger

/** Pure encoding tests for the uncompressed X9.63 public-key form. */
class PublicKeyEncodingTest {
    @Test
    fun encodeRawX962PrefixesAndLeftPads() {
        val raw = AndroidKeyStoreSigner.encodeRawX962(BigInteger.ONE, BigInteger.valueOf(2))
        assertEquals(65, raw.size)
        assertEquals(0x04.toByte(), raw[0]) // uncompressed point marker
        assertEquals(0x01.toByte(), raw[32]) // low byte of X
        assertEquals(0x02.toByte(), raw[64]) // low byte of Y
        assertEquals(0x00.toByte(), raw[1]) // X is left-padded with zero
        assertEquals(0x00.toByte(), raw[33]) // Y is left-padded with zero
    }

    @Test
    fun encodeRawX962StripsTheBigIntegerSignByte() {
        // A 32-byte value with the high bit set carries a leading 0x00 sign byte
        // from BigInteger.toByteArray(); it must be stripped, not shift the point.
        val highBit = BigInteger(1, ByteArray(32) { if (it == 0) 0x80.toByte() else 0x00 })
        val raw = AndroidKeyStoreSigner.encodeRawX962(highBit, BigInteger.ONE)
        assertEquals(65, raw.size)
        assertEquals(0x80.toByte(), raw[1]) // high byte of X, sign byte stripped
        assertEquals(0x01.toByte(), raw[64]) // low byte of Y
    }
}
