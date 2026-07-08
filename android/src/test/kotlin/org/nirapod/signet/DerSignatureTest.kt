// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pure decoder tests for the DER ECDSA to raw `r || s` conversion. Fixed vectors
 * only; the on-device signing path that produces the DER needs an emulator and
 * is not exercised here.
 */
class DerSignatureTest {
    @Test
    fun convertsMinimalIntegersAndLeftPads() {
        // SEQUENCE { INTEGER 0x01, INTEGER 0x02 }
        val der = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)
        val raw = AndroidKeyStoreSigner.derToRawSignature(der)!!
        assertEquals(64, raw.size)
        assertEquals(0x00.toByte(), raw[0]) // r left-padded
        assertEquals(0x01.toByte(), raw[31]) // low byte of r
        assertEquals(0x00.toByte(), raw[32]) // s left-padded
        assertEquals(0x02.toByte(), raw[63]) // low byte of s
    }

    @Test
    fun stripsThePositivePaddingSignByte() {
        // r = 0x80 then 31 zeros, encoded as a 33-byte INTEGER with a 0x00 sign
        // byte; s = 0x01. The sign byte must be stripped, not shift the value.
        val der = ByteArray(40)
        var i = 0
        der[i++] = 0x30
        der[i++] = (2 + 33 + 2 + 1).toByte() // sequence content length = 38
        der[i++] = 0x02
        der[i++] = 0x21 // 33-byte INTEGER
        der[i++] = 0x00 // positive-padding sign byte
        der[i++] = 0x80.toByte() // high bit set
        i += 31 // 31 trailing zeros, already present from allocation
        der[i++] = 0x02
        der[i++] = 0x01
        der[i] = 0x01
        val raw = AndroidKeyStoreSigner.derToRawSignature(der)!!
        assertEquals(64, raw.size)
        assertEquals(0x80.toByte(), raw[0]) // sign byte stripped, value not shifted
        assertEquals(0x00.toByte(), raw[1])
        assertEquals(0x01.toByte(), raw[63])
    }

    @Test
    fun convertsFullWidthComponents() {
        // r and s each a full 32 bytes with no sign byte.
        val r = ByteArray(32) { 0x11 }
        val s = ByteArray(32) { 0x22 }
        val der = byteArrayOf(0x30, (2 + 32 + 2 + 32).toByte(), 0x02, 0x20) +
            r + byteArrayOf(0x02, 0x20) + s
        val raw = AndroidKeyStoreSigner.derToRawSignature(der)!!
        assertArrayEquals(r + s, raw)
    }

    @Test
    fun rejectsMalformedDer() {
        // Wrong SEQUENCE tag.
        assertNull(
            AndroidKeyStoreSigner.derToRawSignature(
                byteArrayOf(0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02),
            ),
        )
        // Declared length does not span the buffer.
        assertNull(
            AndroidKeyStoreSigner.derToRawSignature(
                byteArrayOf(0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02),
            ),
        )
        // Second element is not an INTEGER.
        assertNull(
            AndroidKeyStoreSigner.derToRawSignature(
                byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x02),
            ),
        )
        // Truncated body.
        assertNull(AndroidKeyStoreSigner.derToRawSignature(byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01)))
        // Empty input.
        assertNull(AndroidKeyStoreSigner.derToRawSignature(ByteArray(0)))
    }

    @Test
    fun rejectsAComponentWiderThan32Bytes() {
        // A 33-byte INTEGER of all non-zero bytes cannot be a P-256 scalar.
        val wide = ByteArray(33) { 0x11 }
        val der = byteArrayOf(0x30, (2 + 33 + 2 + 1).toByte(), 0x02, 0x21) +
            wide + byteArrayOf(0x02, 0x01, 0x01)
        assertNull(AndroidKeyStoreSigner.derToRawSignature(der))
    }
}
