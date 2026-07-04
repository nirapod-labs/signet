// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet.kmp

/**
 * A public key in one of the pinned wire formats. There is no matching
 * private-key accessor anywhere in the surface.
 */
public class PublicKey(
    public val format: Format,
    public val bytes: ByteArray,
) {
    /** The public key wire format. */
    public enum class Format {
        /** Uncompressed X9.63 point: `0x04 || X || Y`, 65 bytes for P-256. */
        rawX962,

        /** DER SubjectPublicKeyInfo, 91 bytes for P-256. */
        spki,
    }
}
