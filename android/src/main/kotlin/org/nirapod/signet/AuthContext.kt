// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet

import androidx.fragment.app.FragmentActivity

/**
 * The host-UI context an auth-gated [AndroidKeyStoreSigner.sign] needs to present
 * a biometric prompt. The Android core takes this explicitly (the documented
 * asymmetry versus the implicit-host-UI bindings); it carries the
 * [FragmentActivity] the prompt attaches to and the caller's prompt copy.
 *
 * [authRequirement] must match the requirement the key was created with. The
 * platform Keystore cannot report a key's exact auth class back below API 31;
 * the caller declares it, and it selects the prompt's authenticators. A
 * `biometricOrDeviceCredential` key allows the device credential on API 30+ and
 * is biometric-only below that (a crypto-bound device credential needs API 30).
 * [negativeButtonText] is used only for a biometric-only prompt; supply a
 * localized string.
 */
public class AuthContext(
    public val activity: FragmentActivity,
    public val title: String,
    public val authRequirement: AuthRequirement,
    public val subtitle: String? = null,
    public val negativeButtonText: String = "Cancel",
)
