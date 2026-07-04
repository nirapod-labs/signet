// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

/**
 * The Signet key store: hardware-backed P-256 signing over one contract, the
 * same on every target. `commonMain` declares the surface as `expect`; each
 * platform's `actual` drives its own hardware: the Android Keystore on
 * `androidMain`, the Secure Enclave on `appleMain`, with no key material ever
 * crossing into this layer and no export path anywhere in the surface.
 *
 * The auth-gated `sign` overload (which takes an explicit host-UI context) lands
 * with the biometric surface; this declaration carries the non-gated primitives.
 */
public expect class Signet() {
    /**
     * Creates a non-exportable P-256 key at [KeySpec.alias] and returns it with
     * the tier it achieved. A hard [TierPolicy] the platform cannot meet fails
     * with [SignetErrorCode.unavailableTier]; [TierPolicy.BestEffort] never
     * fails on tier and reports `meetsFloor == false`. An existing alias fails
     * with [SignetErrorCode.keyAlreadyExists]; generation never silently overwrites.
     */
    public fun generateKey(spec: KeySpec): KeyResult

    /** Returns the public key. There is no private-key accessor in the surface. */
    public fun getPublicKey(handle: KeyHandle, format: PublicKey.Format = PublicKey.Format.rawX962): PublicKey

    /**
     * Signs a 32-byte digest with the key at [handle]. The caller hashes; a
     * digest that is not exactly 32 bytes fails with
     * [SignetErrorCode.invalidArgument] before any hardware call. This overload
     * is for a key with no presence check; an auth-gated key is signed through
     * the gated overload.
     */
    public fun sign(handle: KeyHandle, digest: ByteArray, options: SignOptions = SignOptions()): ByteArray

    /**
     * Re-reads the tier report for a live or invalidated key. Never throws on an
     * invalidated-but-present key: the report carries `invalidated == true`,
     * while `sign` and `getAttestation` on that key raise
     * [SignetErrorCode.keyInvalidated].
     */
    public fun getSecurityTier(handle: KeyHandle): SecurityTierReport

    /**
     * Produces the key's attestation; this library never verifies it. The
     * challenge was bound at [generateKey]; this call takes none. `format` is
     * `androidKeyChain` where a chain exists and `none` otherwise (the Secure
     * Enclave has no per-key attestation).
     */
    public fun getAttestation(handle: KeyHandle): AttestationResult

    /** Whether a key exists for [alias], without materializing a handle. */
    public fun exists(alias: String): Boolean

    /** Deletes the key for [alias]. Idempotent: a missing alias is not an error. */
    public fun delete(alias: String)
}
