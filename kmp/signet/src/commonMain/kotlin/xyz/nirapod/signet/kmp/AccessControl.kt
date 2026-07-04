// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet.kmp

/** The presence check a caller requests on a key. */
public enum class AuthRequirement {
    none,
    biometricOnly,
    biometricOrDeviceCredential,
}

/**
 * Access-control policy for a key. `authValiditySeconds` null or 0 means per-use
 * auth; a positive value is a time window. `invalidateOnBiometricEnrollment`
 * (default true) invalidates the key when the biometric set changes.
 */
public class AccessControlPolicy(
    public val authRequirement: AuthRequirement,
    public val authValiditySeconds: Int? = null,
    public val invalidateOnBiometricEnrollment: Boolean = true,
) {
    public companion object {
        /** No presence check. */
        public val None: AccessControlPolicy = AccessControlPolicy(AuthRequirement.none)
    }
}
