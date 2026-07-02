// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

/**
 * Signet Kotlin Multiplatform binding entry point.
 *
 * Scaffold: exercises expect/actual across every target with no key material
 * and no export symbol declared anywhere in this module. The hardware-signer
 * surface is added later against the conformance contract.
 */
public object Signet {
    /** Library version, aligned with the repository VERSION file. */
    public const val VERSION: String = "0.1.0-dev"
}

/** Returns the platform tag of the active Signet target. */
public expect fun platformTag(): String
