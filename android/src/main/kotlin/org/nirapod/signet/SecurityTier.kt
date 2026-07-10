// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet

/**
 * The hardware backing a signing key, reported as the achieved level and never
 * assumed from the request. Closed set; see `conformance/security-level.json`.
 */
public enum class SecurityLevel {
    strongBox,
    tee,
}

/**
 * How the achieved [SecurityLevel] was determined. The Android core reads the
 * level back from the created key via the platform Keystore.
 */
public enum class TierEvidence {
    keyInfoReadback,
}

/**
 * The presence check bound to a key at creation, derived from the created key
 * and never echoed from the request.
 */
public enum class AuthClass {
    none,
    biometricOnly,
    biometricOrDeviceCredential,
    deviceCredentialOnly,
}

/**
 * A class in the tier partial order. `atLeast` selects by class: `discreteSecure`
 * covers StrongBox and outranks `trustedEnvironment`, which covers the TEE.
 */
public enum class HardwareClass(internal val rank: Int) {
    discreteSecure(0),
    trustedEnvironment(1),
}

/**
 * The partial-order class a level belongs to. Total over the hardware-only level
 * set: StrongBox is `discreteSecure`, the TEE is `trustedEnvironment`.
 */
internal val SecurityLevel.hardwareClass: HardwareClass
    get() = when (this) {
        SecurityLevel.strongBox -> HardwareClass.discreteSecure
        SecurityLevel.tee -> HardwareClass.trustedEnvironment
    }

/**
 * Tier selection on [KeySpec]. Selection is by class, never a concrete
 * [SecurityLevel]; the achieved level is reported in [SecurityTierReport].
 */
public sealed class TierPolicy {
    /**
     * The device's best hardware tier. A StrongBox device that falls back to the
     * TEE fails `unavailableTier` rather than silently downgrade.
     */
    public object Strongest : TierPolicy()

    /** A hard floor by class. Fails `unavailableTier` below the class. */
    public data class AtLeast(val hardwareClass: HardwareClass) : TierPolicy()

    /** Whether [achieved] satisfies this policy's floor, per the partial order. */
    internal fun isMet(achieved: SecurityLevel, platformStrongest: SecurityLevel): Boolean =
        when (this) {
            Strongest -> achieved == platformStrongest
            is AtLeast -> achieved.hardwareClass.rank <= hardwareClass.rank
        }
}

/**
 * One report shape everywhere. `achieved` is read back from the created key and
 * `authEnforced` is derived from the created key.
 *
 * `requested` is optional: `generateKey` populates it; a `getSecurityTier`
 * re-read leaves it null, since the policy is not stored with the key. The
 * Android core reads `authEnforced` back from the key. A null `authEnforced` in
 * the shared report shape means unobservable, distinct from [AuthClass.none] (a
 * key created with no presence check).
 */
public data class SecurityTierReport(
    val achieved: SecurityLevel,
    val requested: TierPolicy?,
    val evidence: TierEvidence,
    val authEnforced: AuthClass?,
    val invalidated: Boolean,
    val schemaVersion: Int = 1,
)
