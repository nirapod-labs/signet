// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

/**
 * A key generation request. Tier is selected by [tierPolicy] (class-based, not a
 * concrete level); [accessControl] sets the presence check bound to the key.
 * [attestationChallenge], when set, is bound into the key at generation; there
 * is no call-time challenge.
 */
public class KeySpec(
    public val alias: String,
    public val tierPolicy: TierPolicy = TierPolicy.Strongest,
    public val accessControl: AccessControlPolicy = AccessControlPolicy.None,
    public val attestationChallenge: ByteArray? = null,
)

/**
 * An opaque reference to a generated key. It carries only the alias; the key
 * material stays in hardware and is addressed by name at the key store.
 */
public class KeyHandle internal constructor(public val alias: String)
