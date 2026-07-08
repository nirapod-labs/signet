// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet

import org.junit.Assert.assertTrue
import org.junit.Test

class SignetTest {
    @Test
    fun versionIsSet() {
        assertTrue(Signet.VERSION.isNotEmpty())
    }
}
