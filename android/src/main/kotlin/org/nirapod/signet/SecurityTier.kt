// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet

/**
 * The hardware backing a signing key, reported as the achieved level and never
 * assumed from the request. Closed set; see `conformance/security-level.json`.
 */
public enum class SecurityLevel {
    secureEnclave,
    strongBox,
    tee,
    tpm,
    software,
}

/**
 * How the achieved [SecurityLevel] was determined. Only `attested` is
 * cryptographic proof; every other value is an on-device self-report.
 */
public enum class TierEvidence {
    attested,
    keyInfoReadback,
    seTokenPresent,
    inferred,
    selfReportUnverified,
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
 * covers Secure Enclave, StrongBox, and TPM, and outranks `trustedEnvironment`.
 */
public enum class HardwareClass(internal val rank: Int) {
    discreteSecure(0),
    trustedEnvironment(1),
}

/**
 * The partial-order class a level belongs to, or null for `software`, which is
 * below every hardware class.
 */
internal val SecurityLevel.hardwareClass: HardwareClass?
    get() = when (this) {
        SecurityLevel.secureEnclave, SecurityLevel.strongBox, SecurityLevel.tpm ->
            HardwareClass.discreteSecure
        SecurityLevel.tee -> HardwareClass.trustedEnvironment
        SecurityLevel.software -> null
    }

/**
 * Tier selection on [KeySpec]. Selection is by class, never a concrete
 * [SecurityLevel]; the achieved level is reported in [SecurityTierReport].
 */
public sealed class TierPolicy {
    /** The device's best hardware tier. Fails `unavailableTier` if none exists; never software. */
    public object Strongest : TierPolicy()

    /** A hard floor by class. Fails `unavailableTier` below the class. */
    public data class AtLeast(val hardwareClass: HardwareClass) : TierPolicy()

    /** Never fails on tier; may return a weaker level with `meetsFloor == false` and honest evidence. */
    public object BestEffort : TierPolicy()

    /** Whether [achieved] satisfies this policy's floor, per the partial order. */
    internal fun isMet(achieved: SecurityLevel, platformStrongest: SecurityLevel): Boolean =
        when (this) {
            Strongest -> achieved == platformStrongest
            is AtLeast -> {
                val achievedClass = achieved.hardwareClass
                achievedClass != null && achievedClass.rank <= hardwareClass.rank
            }
            BestEffort -> achieved.hardwareClass == HardwareClass.discreteSecure
        }
}

/**
 * One report shape everywhere. `achieved` is read back from the created key,
 * `meetsFloor` derives from the tier partial order, and `authEnforced` is
 * derived from the created key.
 *
 * `requested` and `authEnforced` are optional. `generateKey` populates both; a
 * `getSecurityTier` re-read leaves `requested` null (the policy is not stored
 * with the key) and, on a platform without a created-key read-back, `authEnforced`
 * null. A null `authEnforced` means unobservable, distinct from [AuthClass.none]
 * (a key created with no presence check).
 */
public data class SecurityTierReport(
    val achieved: SecurityLevel,
    val requested: TierPolicy?,
    val meetsFloor: Boolean,
    val evidence: TierEvidence,
    val authEnforced: AuthClass?,
    val invalidated: Boolean,
    val schemaVersion: Int = 1,
)
