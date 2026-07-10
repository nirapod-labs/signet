// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet.kmp

import android.content.Context
import org.nirapod.signet.AndroidKeyStoreSigner
import org.nirapod.signet.AccessControlPolicy as CoreAccessControlPolicy
import org.nirapod.signet.AttestationResult as CoreAttestationResult
import org.nirapod.signet.AuthClass as CoreAuthClass
import org.nirapod.signet.AuthRequirement as CoreAuthRequirement
import org.nirapod.signet.HardwareClass as CoreHardwareClass
import org.nirapod.signet.KeyHandle as CoreKeyHandle
import org.nirapod.signet.KeySpec as CoreKeySpec
import org.nirapod.signet.PublicKey as CorePublicKey
import org.nirapod.signet.SecurityLevel as CoreSecurityLevel
import org.nirapod.signet.SecurityTierReport as CoreSecurityTierReport
import org.nirapod.signet.SignOptions as CoreSignOptions
import org.nirapod.signet.SignetErrorCode as CoreSignetErrorCode
import org.nirapod.signet.SignetException as CoreSignetException
import org.nirapod.signet.TierEvidence as CoreTierEvidence
import org.nirapod.signet.TierPolicy as CoreTierPolicy

/**
 * Android `actual`: delegates to the AndroidKeyStore core and translates between
 * the core's `org.nirapod.signet` contract types and this module's
 * `org.nirapod.signet.kmp` types. No key handling is re-implemented in this layer.
 */
public actual class Signet(context: Context) {
    private val signer = AndroidKeyStoreSigner(context)

    public actual fun generateKey(spec: KeySpec): KeyResult = translatingErrors {
        val (handle, report) = signer.generateKey(spec.toCore())
        KeyResult(KeyHandle(handle.alias), report.toKmp())
    }

    public actual fun getPublicKey(handle: KeyHandle, format: PublicKey.Format): PublicKey =
        translatingErrors { signer.getPublicKey(CoreKeyHandle(handle.alias), format.toCore()).toKmp() }

    public actual fun sign(handle: KeyHandle, digest: ByteArray, options: SignOptions): ByteArray =
        translatingErrors { signer.sign(CoreKeyHandle(handle.alias), digest, options.toCore()) }

    public actual suspend fun sign(
        handle: KeyHandle,
        digest: ByteArray,
        authContext: AuthContext,
        options: SignOptions,
    ): ByteArray = translatingErrors {
        signer.sign(CoreKeyHandle(handle.alias), digest, authContext.core, options.toCore())
    }

    public actual fun getSecurityTier(handle: KeyHandle): SecurityTierReport =
        translatingErrors { signer.getSecurityTier(CoreKeyHandle(handle.alias)).toKmp() }

    public actual fun getAttestation(handle: KeyHandle): AttestationResult =
        translatingErrors { signer.getAttestation(CoreKeyHandle(handle.alias)).toKmp() }

    public actual fun exists(alias: String): Boolean = translatingErrors { signer.exists(alias) }

    public actual fun delete(alias: String) {
        translatingErrors { signer.delete(alias) }
    }
}

/** Re-throws a core [CoreSignetException] as this module's [SignetException]. */
private inline fun <T> translatingErrors(block: () -> T): T =
    try {
        block()
    } catch (e: CoreSignetException) {
        throw SignetException(e.code.toKmp(), e.message, e.cause)
    }

internal fun KeySpec.toCore(): CoreKeySpec =
    CoreKeySpec(alias, tierPolicy.toCore(), accessControl.toCore(), attestationChallenge)

internal fun TierPolicy.toCore(): CoreTierPolicy = when (this) {
    TierPolicy.Strongest -> CoreTierPolicy.Strongest
    is TierPolicy.AtLeast -> CoreTierPolicy.AtLeast(hardwareClass.toCore())
}

internal fun HardwareClass.toCore(): CoreHardwareClass = when (this) {
    HardwareClass.discreteSecure -> CoreHardwareClass.discreteSecure
    HardwareClass.trustedEnvironment -> CoreHardwareClass.trustedEnvironment
}

internal fun AccessControlPolicy.toCore(): CoreAccessControlPolicy =
    CoreAccessControlPolicy(authRequirement.toCore(), authValiditySeconds, invalidateOnBiometricEnrollment)

internal fun AuthRequirement.toCore(): CoreAuthRequirement = when (this) {
    AuthRequirement.none -> CoreAuthRequirement.none
    AuthRequirement.biometricOnly -> CoreAuthRequirement.biometricOnly
    AuthRequirement.biometricOrDeviceCredential -> CoreAuthRequirement.biometricOrDeviceCredential
}

internal fun PublicKey.Format.toCore(): CorePublicKey.Format = when (this) {
    PublicKey.Format.rawX962 -> CorePublicKey.Format.rawX962
    PublicKey.Format.spki -> CorePublicKey.Format.spki
}

internal fun SignOptions.toCore(): CoreSignOptions = CoreSignOptions(encoding.toCore())

internal fun SignOptions.Encoding.toCore(): CoreSignOptions.Encoding = when (this) {
    SignOptions.Encoding.der -> CoreSignOptions.Encoding.der
    SignOptions.Encoding.rawRS -> CoreSignOptions.Encoding.rawRS
}

internal fun CoreSecurityTierReport.toKmp(): SecurityTierReport = SecurityTierReport(
    achieved = achieved.toKmp(),
    requested = requested?.toKmp(),
    evidence = evidence.toKmp(),
    authEnforced = authEnforced?.toKmp(),
    invalidated = invalidated,
    schemaVersion = schemaVersion,
)

internal fun CoreSecurityLevel.toKmp(): SecurityLevel = when (this) {
    CoreSecurityLevel.strongBox -> SecurityLevel.strongBox
    CoreSecurityLevel.tee -> SecurityLevel.tee
}

internal fun CoreTierPolicy.toKmp(): TierPolicy = when (this) {
    CoreTierPolicy.Strongest -> TierPolicy.Strongest
    is CoreTierPolicy.AtLeast -> TierPolicy.AtLeast(hardwareClass.toKmp())
}

internal fun CoreHardwareClass.toKmp(): HardwareClass = when (this) {
    CoreHardwareClass.discreteSecure -> HardwareClass.discreteSecure
    CoreHardwareClass.trustedEnvironment -> HardwareClass.trustedEnvironment
}

internal fun CoreTierEvidence.toKmp(): TierEvidence = when (this) {
    CoreTierEvidence.keyInfoReadback -> TierEvidence.keyInfoReadback
}

internal fun CoreAuthClass.toKmp(): AuthClass = when (this) {
    CoreAuthClass.none -> AuthClass.none
    CoreAuthClass.biometricOnly -> AuthClass.biometricOnly
    CoreAuthClass.biometricOrDeviceCredential -> AuthClass.biometricOrDeviceCredential
    CoreAuthClass.deviceCredentialOnly -> AuthClass.deviceCredentialOnly
}

internal fun CorePublicKey.toKmp(): PublicKey = PublicKey(format.toKmp(), bytes)

internal fun CorePublicKey.Format.toKmp(): PublicKey.Format = when (this) {
    CorePublicKey.Format.rawX962 -> PublicKey.Format.rawX962
    CorePublicKey.Format.spki -> PublicKey.Format.spki
}

internal fun CoreAttestationResult.toKmp(): AttestationResult =
    AttestationResult(format.toKmp(), chain, schemaVersion)

internal fun CoreAttestationResult.Format.toKmp(): AttestationResult.Format = when (this) {
    CoreAttestationResult.Format.androidKeyChain -> AttestationResult.Format.androidKeyChain
    CoreAttestationResult.Format.none -> AttestationResult.Format.none
}

internal fun CoreSignetErrorCode.toKmp(): SignetErrorCode = when (this) {
    CoreSignetErrorCode.unavailableTier -> SignetErrorCode.unavailableTier
    CoreSignetErrorCode.userCanceled -> SignetErrorCode.userCanceled
    CoreSignetErrorCode.keyInvalidated -> SignetErrorCode.keyInvalidated
    CoreSignetErrorCode.authFailed -> SignetErrorCode.authFailed
    CoreSignetErrorCode.authContextRequired -> SignetErrorCode.authContextRequired
    CoreSignetErrorCode.notFound -> SignetErrorCode.notFound
    CoreSignetErrorCode.keyAlreadyExists -> SignetErrorCode.keyAlreadyExists
    CoreSignetErrorCode.tierMismatchOnExisting -> SignetErrorCode.tierMismatchOnExisting
    CoreSignetErrorCode.attestationUnsupported -> SignetErrorCode.attestationUnsupported
    CoreSignetErrorCode.hardwareError -> SignetErrorCode.hardwareError
    CoreSignetErrorCode.unsupportedPlatform -> SignetErrorCode.unsupportedPlatform
    CoreSignetErrorCode.invalidArgument -> SignetErrorCode.invalidArgument
    CoreSignetErrorCode.authInProgress -> SignetErrorCode.authInProgress
}
