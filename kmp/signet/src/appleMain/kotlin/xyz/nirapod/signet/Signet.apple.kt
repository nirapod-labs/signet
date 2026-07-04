// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

/**
 * Apple `actual`, shared across the iOS, macOS, and watchOS targets. The Secure
 * Enclave path is re-implemented over Security.framework in Kotlin/Native in a
 * later change; these bodies are unimplemented placeholders that keep
 * `commonMain` compiling. They hold no key material and are unreachable until
 * the Secure Enclave path lands.
 */
public actual class Signet actual constructor() {
    public actual fun generateKey(spec: KeySpec): KeyResult = TODO("appleMain: re-implement the Secure Enclave path over Security.framework")

    public actual fun getPublicKey(handle: KeyHandle, format: PublicKey.Format): PublicKey = TODO("appleMain")

    public actual fun sign(handle: KeyHandle, digest: ByteArray, options: SignOptions): ByteArray = TODO("appleMain")

    public actual fun getSecurityTier(handle: KeyHandle): SecurityTierReport = TODO("appleMain")

    public actual fun getAttestation(handle: KeyHandle): AttestationResult = TODO("appleMain")

    public actual fun exists(alias: String): Boolean = TODO("appleMain")

    public actual fun delete(alias: String) {
        TODO("appleMain")
    }
}
