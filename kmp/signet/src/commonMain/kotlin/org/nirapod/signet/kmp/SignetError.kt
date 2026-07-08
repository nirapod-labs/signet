// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet.kmp

/**
 * The one closed error set every Signet core and binding raises.
 *
 * Entry names and spelling (`userCanceled`, one `l`) are fixed by the
 * cross-language contract in `conformance/errors.json`; they are camel case to
 * match that wire contract, not Kotlin enum convention. A binding maps a
 * structured code to its idiomatic form without interpreting platform
 * exceptions.
 */
public enum class SignetErrorCode {
    /** The requested hardware tier is not available and no downgrade applies. */
    unavailableTier,

    /** The user dismissed the authentication prompt. */
    userCanceled,

    /** The key was invalidated, for example by biometric re-enrollment. */
    keyInvalidated,

    /** Authentication was attempted and failed. */
    authFailed,

    /** An auth-gated operation was invoked with no host UI context available. */
    authContextRequired,

    /** No key exists for the given alias. */
    notFound,

    /** A key already exists for the alias; generation does not overwrite. */
    keyAlreadyExists,

    /** An existing key does not match the requested tier. */
    tierMismatchOnExisting,

    /** Attestation is not supported for this key or platform. */
    attestationUnsupported,

    /** A platform key-store or hardware operation failed. */
    hardwareError,

    /** The operation is not supported on this platform. */
    unsupportedPlatform,

    /**
     * The caller violated a locally-checkable precondition, for example a digest
     * that is not exactly 32 bytes. Rejected before any platform call; never
     * conflated with [hardwareError].
     */
    invalidArgument,

    /**
     * An auth-gated operation was issued while another's biometric prompt was
     * still outstanding. Auth-gated signing is serialized; the concurrent
     * request is rejected rather than queued behind or racing the first prompt.
     */
    authInProgress,
}

/**
 * The exception every Signet operation throws, carrying one [SignetErrorCode].
 * Callers match on [code] structurally; the code is never string-matched.
 */
public class SignetException(
    public val code: SignetErrorCode,
    message: String? = null,
    cause: Throwable? = null,
) : Exception(message ?: code.name, cause)
