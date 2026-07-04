// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet.kmp

/**
 * The platform host-UI context an auth-gated [Signet.sign] presents its biometric
 * prompt through. Construction is platform-specific and never happens in common
 * code, the same asymmetry as [Signet]: an Android caller builds
 * `AuthContext(activity, title, authRequirement, ...)` carrying the
 * `FragmentActivity` the prompt attaches to; an Apple caller builds
 * `AuthContext(title, authRequirement, ...)`; the Secure Enclave presents
 * the prompt itself. `authRequirement` must match the requirement the key was
 * created with and selects the prompt's authenticators. Common code receives a
 * constructed instance and passes it to [Signet.sign].
 */
public expect class AuthContext
