// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet.kmp

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
 *
 * The constructor is public: a handle is a reconstructible token, not a live
 * reference. A binding that persisted the alias rebuilds the handle across
 * process restarts without holding the original object. Building a handle grants
 * no access on its own; it names a key, and `exists`, `delete`, and
 * `getSecurityTier` already address a key by alias.
 */
public class KeyHandle(public val alias: String)
