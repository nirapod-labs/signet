// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

/**
 * Options for [AndroidKeyStoreSigner.sign]. `normalizeLowS` is part of the
 * cross-language contract but is not exposed here yet; it lands with the shared
 * low-S implementation once its byte-exact conformance vector is green across
 * every binding.
 */
public class SignOptions(
    public val encoding: Encoding = Encoding.der,
) {
    /** The signature wire format. */
    public enum class Encoding {
        /** X9.62 DER `SEQUENCE { INTEGER r, INTEGER s }` (the Keystore's output). */
        der,

        /** Fixed 64-byte `r || s`, each a 32-byte big-endian integer. */
        rawRS,
    }
}
