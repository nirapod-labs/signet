// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Serializes auth-gated signing. A biometric prompt owns the foreground; only
 * one auth-gated sign may be outstanding at a time, and a second concurrent
 * attempt is rejected rather than queued behind or racing the first prompt.
 */
internal class AuthSignGate {
    private val busy = AtomicBoolean(false)

    /** Acquires the gate. Returns false if a gated sign is already in progress. */
    fun tryEnter(): Boolean = busy.compareAndSet(false, true)

    /** Releases the gate for the next auth-gated sign. */
    fun exit() {
        busy.set(false)
    }
}
