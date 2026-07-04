// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet.kmp

/**
 * Apple `actual`: the prompt the Secure Enclave presents for an auth-gated sign.
 * There is no activity; the Enclave draws and authenticates the prompt itself;
 * this carries only the prompt copy and the requirement that selects it.
 */
public actual class AuthContext(
    internal val title: String,
    internal val authRequirement: AuthRequirement,
    internal val subtitle: String? = null,
    internal val negativeButtonText: String = "Cancel",
)
