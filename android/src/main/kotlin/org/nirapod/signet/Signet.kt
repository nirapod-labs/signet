// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet

/**
 * Signet Android core entry point.
 *
 * The hardware-backed P-256 surface ships in [AndroidKeyStoreSigner]: key
 * generation in the platform Keystore (StrongBox where available, otherwise the
 * TEE), silent and auth-gated signing over `BiometricPrompt`, tier read-back,
 * and X.509 key attestation. There is no software-key path; a request that
 * cannot be met in secure hardware fails closed. This object exposes only the
 * library version.
 */
public object Signet {
    /** Library version, aligned with the repository VERSION file. */
    public const val VERSION: String = "0.1.0-dev"
}
