// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

import kotlin.test.Test
import kotlin.test.assertTrue

class SignetTest {
    @Test
    fun versionIsSet() {
        assertTrue(Signet.VERSION.isNotEmpty())
    }

    @Test
    fun platformTagIsSet() {
        assertTrue(platformTag().isNotEmpty())
    }
}
