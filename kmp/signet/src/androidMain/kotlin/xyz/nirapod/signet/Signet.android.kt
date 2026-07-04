// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

/**
 * Android `actual`. Delegation to the AndroidKeyStore core is wired in a later
 * change; these bodies are unimplemented placeholders that keep `commonMain`
 * compiling. They hold no key material and are unreachable until the core is
 * delegated to.
 */
public actual class Signet actual constructor() {
    public actual fun generateKey(spec: KeySpec): KeyResult = TODO("androidMain: delegate to the AndroidKeyStore core")

    public actual fun getPublicKey(handle: KeyHandle, format: PublicKey.Format): PublicKey = TODO("androidMain")

    public actual fun sign(handle: KeyHandle, digest: ByteArray, options: SignOptions): ByteArray = TODO("androidMain")

    public actual fun getSecurityTier(handle: KeyHandle): SecurityTierReport = TODO("androidMain")

    public actual fun getAttestation(handle: KeyHandle): AttestationResult = TODO("androidMain")

    public actual fun exists(alias: String): Boolean = TODO("androidMain")

    public actual fun delete(alias: String) {
        TODO("androidMain")
    }
}
