// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet.kmp

/**
 * The result of [Signet.getAttestation]. A hardware key-attestation certificate
 * chain (`androidKeyChain`) is produced only for a key created with an
 * attestation challenge; otherwise `format` is `none` with an empty chain. The
 * challenge is bound at key generation, never here.
 *
 * A plain class, not a data class: `chain` holds raw certificate bytes, where a
 * generated `equals` over array identity would mislead.
 */
public class AttestationResult(
    public val format: Format,
    public val chain: List<ByteArray> = emptyList(),
    public val schemaVersion: Int = 1,
) {
    /** The attestation wire format. */
    public enum class Format {
        /** A hardware key-attestation certificate chain. */
        androidKeyChain,

        /** No attestation is available for this key. */
        none,
    }
}
