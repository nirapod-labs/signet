// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet.kmp

import androidx.fragment.app.FragmentActivity
import xyz.nirapod.signet.AuthContext as CoreAuthContext

/**
 * Android `actual`: carries the [FragmentActivity] the biometric prompt attaches
 * to and builds the core `AuthContext` the gated sign drives. Translates the
 * module's [AuthRequirement] to the core's; no prompt logic lives here.
 */
public actual class AuthContext(
    activity: FragmentActivity,
    title: String,
    authRequirement: AuthRequirement,
    subtitle: String? = null,
    negativeButtonText: String = "Cancel",
) {
    internal val core: CoreAuthContext = CoreAuthContext(
        activity,
        title,
        authRequirement.toCore(),
        subtitle,
        negativeButtonText,
    )
}
