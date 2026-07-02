// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

/**
 * Signet Android core entry point.
 *
 * Scaffold: the module compiles with no AndroidKeyStore access and no export
 * symbol declared anywhere. The hardware-backed P-256 surface, the StrongBox to
 * TEE ladder, and key attestation are added with the key code and proven in
 * tests.
 */
public object Signet {
    /** Library version, aligned with the repository VERSION file. */
    public const val VERSION: String = "0.1.0-dev"
}
