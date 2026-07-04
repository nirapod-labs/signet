// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet.kmp

/** [Signet.generateKey]'s result: the [handle] to the new key paired with the [report] for the tier it achieved. */
public data class KeyResult(
    val handle: KeyHandle,
    val report: SecurityTierReport,
)
