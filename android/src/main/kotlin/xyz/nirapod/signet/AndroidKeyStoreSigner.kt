// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Android Keystore-backed P-256 key store.
 *
 * Keys are created non-exportable in the platform Keystore (StrongBox where
 * available, otherwise the TEE). There is no export path: the outputs are a
 * handle, a public key, a signature, and attestation, never private-key bytes.
 * The achieved tier is read back from the created key, never assumed; a hard
 * tier policy that cannot be met fails `unavailableTier` and never returns a
 * weaker key.
 */
public class AndroidKeyStoreSigner(private val context: Context) {
    /**
     * Generates a non-exportable P-256 key, gated by the spec's access-control
     * policy. Tries StrongBox first and falls back to the TEE; the report's
     * `achieved` is read back from the created key.
     *
     * @throws SignetException `keyAlreadyExists` if the alias is taken;
     *   `unavailableTier` if a hard tier policy cannot be met; `hardwareError`
     *   if the Keystore rejects creation.
     */
    public fun generateKey(spec: KeySpec): Pair<KeyHandle, SecurityTierReport> {
        if (exists(spec.alias)) {
            throw SignetException(SignetErrorCode.keyAlreadyExists)
        }
        val entryAlias = keystoreAlias(spec.alias)
        val deviceHasStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val (privateKey, strongBoxUsed) = try {
            if (deviceHasStrongBox) {
                try {
                    createKey(entryAlias, spec, strongBox = true) to true
                } catch (unavailable: StrongBoxUnavailableException) {
                    createKey(entryAlias, spec, strongBox = false) to false
                }
            } else {
                createKey(entryAlias, spec, strongBox = false) to false
            }
        } catch (failure: Exception) {
            throw SignetException(SignetErrorCode.hardwareError, cause = failure)
        }

        val keyInfo = keyInfoOf(privateKey)
        val achieved = securityLevel(keyInfo, strongBoxUsed)
        // The device's strongest achievable tier: StrongBox where the hardware
        // has it, otherwise the TEE. `strongest` must match this; a StrongBox
        // device that fell back to the TEE fails rather than silently downgrade.
        val platformStrongest =
            if (deviceHasStrongBox) SecurityLevel.strongBox else SecurityLevel.tee
        val meetsFloor = spec.tierPolicy.isMet(achieved, platformStrongest)
        // A hard policy (strongest / atLeast) fails closed below its floor; it
        // never hands back a weaker key. bestEffort never fails on tier.
        if (spec.tierPolicy !is TierPolicy.BestEffort && !meetsFloor) {
            deleteEntry(entryAlias)
            throw SignetException(SignetErrorCode.unavailableTier)
        }

        val report = SecurityTierReport(
            achieved = achieved,
            requested = spec.tierPolicy,
            meetsFloor = meetsFloor,
            evidence = if (achieved == SecurityLevel.software) {
                TierEvidence.selfReportUnverified
            } else {
                TierEvidence.keyInfoReadback
            },
            authEnforced = authClass(keyInfo),
            invalidated = false,
        )
        return KeyHandle(spec.alias) to report
    }

    /**
     * Returns the public key for a handle. `rawX962` is the uncompressed point;
     * `spki` is the SubjectPublicKeyInfo. There is no private-key accessor.
     *
     * @throws SignetException `notFound` if no key exists; `hardwareError` if the
     *   public key cannot be read.
     */
    public fun getPublicKey(
        handle: KeyHandle,
        format: PublicKey.Format = PublicKey.Format.rawX962,
    ): PublicKey {
        val certificate = keyStore().getCertificate(keystoreAlias(handle.alias))
            ?: throw SignetException(SignetErrorCode.notFound)
        val publicKey = certificate.publicKey as? ECPublicKey
            ?: throw SignetException(SignetErrorCode.hardwareError)
        return when (format) {
            PublicKey.Format.rawX962 ->
                PublicKey(format, encodeRawX962(publicKey.w.affineX, publicKey.w.affineY))
            PublicKey.Format.spki ->
                PublicKey(format, publicKey.encoded)
        }
    }

    /** Reports whether a key exists for the alias. */
    public fun exists(alias: String): Boolean = keyStore().containsAlias(keystoreAlias(alias))

    /**
     * Deletes the key for the alias. Idempotent: a missing key is a success.
     *
     * @throws SignetException `hardwareError` if the key store rejects the delete
     *   for a reason other than the key being absent.
     */
    public fun delete(alias: String) {
        val store = keyStore()
        val entryAlias = keystoreAlias(alias)
        if (!store.containsAlias(entryAlias)) return
        try {
            store.deleteEntry(entryAlias)
        } catch (failure: Exception) {
            throw SignetException(SignetErrorCode.hardwareError, cause = failure)
        }
    }

    /**
     * Loads the private-key reference for an alias. Internal by design: the
     * private key is used in-process and never returned to a caller.
     *
     * @throws SignetException `notFound` if no key exists; `hardwareError` on any
     *   other key-store failure.
     */
    internal fun loadPrivateKey(alias: String): PrivateKey {
        val store = keyStore()
        val entryAlias = keystoreAlias(alias)
        if (!store.containsAlias(entryAlias)) throw SignetException(SignetErrorCode.notFound)
        val entry = try {
            store.getEntry(entryAlias, null) as? KeyStore.PrivateKeyEntry
        } catch (failure: Exception) {
            throw SignetException(SignetErrorCode.hardwareError, cause = failure)
        }
        return entry?.privateKey ?: throw SignetException(SignetErrorCode.hardwareError)
    }

    private fun createKey(entryAlias: String, spec: KeySpec, strongBox: Boolean): PrivateKey {
        val builder = KeyGenParameterSpec.Builder(entryAlias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
        if (strongBox) {
            builder.setIsStrongBoxBacked(true)
        }
        applyAccessControl(builder, spec.accessControl)
        spec.attestationChallenge?.let { builder.setAttestationChallenge(it) }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        generator.initialize(builder.build())
        return generator.generateKeyPair().private
    }

    private fun applyAccessControl(builder: KeyGenParameterSpec.Builder, policy: AccessControlPolicy) {
        if (policy.authRequirement == AuthRequirement.none) return
        builder.setUserAuthenticationRequired(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val authType = when (policy.authRequirement) {
                AuthRequirement.biometricOnly -> KeyProperties.AUTH_BIOMETRIC_STRONG
                AuthRequirement.biometricOrDeviceCredential ->
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                AuthRequirement.none -> 0
            }
            builder.setUserAuthenticationParameters(policy.authValiditySeconds ?: 0, authType)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(
                policy.authValiditySeconds?.takeIf { it > 0 } ?: -1,
            )
        }
        if (policy.invalidateOnBiometricEnrollment) {
            builder.setInvalidatedByBiometricEnrollment(true)
        }
    }

    private fun keyInfoOf(privateKey: PrivateKey): KeyInfo {
        val factory = KeyFactory.getInstance(privateKey.algorithm, PROVIDER)
        return factory.getKeySpec(privateKey, KeyInfo::class.java)
    }

    /**
     * The achieved tier, read back from the created key. On API 31+ the Keystore
     * reports the level directly; below that, a successful StrongBox creation is
     * the StrongBox signal and `isInsideSecureHardware` distinguishes TEE from
     * software.
     */
    private fun securityLevel(keyInfo: KeyInfo, strongBoxUsed: Boolean): SecurityLevel {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return securityLevelFromCode(keyInfo.securityLevel)
        }
        @Suppress("DEPRECATION")
        return when {
            strongBoxUsed -> SecurityLevel.strongBox
            keyInfo.isInsideSecureHardware -> SecurityLevel.tee
            else -> SecurityLevel.software
        }
    }

    /**
     * The auth class of the created key, read from its [KeyInfo] and never echoed
     * from the request. Below API 31 the Keystore does not expose the auth type;
     * an auth-required key reports `biometricOnly` as a floor, not an exact class
     * (a device-credential key cannot be distinguished there).
     */
    private fun authClass(keyInfo: KeyInfo): AuthClass {
        if (!keyInfo.isUserAuthenticationRequired) return AuthClass.none
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val type = keyInfo.userAuthenticationType
            val biometric = (type and KeyProperties.AUTH_BIOMETRIC_STRONG) != 0
            val credential = (type and KeyProperties.AUTH_DEVICE_CREDENTIAL) != 0
            return when {
                biometric && credential -> AuthClass.biometricOrDeviceCredential
                credential -> AuthClass.deviceCredentialOnly
                else -> AuthClass.biometricOnly
            }
        }
        return AuthClass.biometricOnly
    }

    private fun deleteEntry(entryAlias: String) {
        try {
            keyStore().deleteEntry(entryAlias)
        } catch (_: Exception) {
            // Best-effort cleanup of a below-floor key before failing closed.
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun keystoreAlias(alias: String): String = TAG_PREFIX + alias

    internal companion object {
        private const val PROVIDER = "AndroidKeyStore"

        /**
         * Namespaces the Keystore alias; without the prefix, Signet keys would
         * collide with other keys the host app stores under the same provider.
         */
        private const val TAG_PREFIX = "nirapod.signet."

        /** Maps a `KeyInfo.getSecurityLevel()` code (API 31+) to a [SecurityLevel]. */
        internal fun securityLevelFromCode(level: Int): SecurityLevel = when (level) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.strongBox
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.tee
            else -> SecurityLevel.software
        }

        /**
         * Encodes an EC point as the uncompressed X9.63 form `0x04 || X || Y`,
         * each coordinate a 32-byte big-endian integer.
         */
        internal fun encodeRawX962(x: BigInteger, y: BigInteger): ByteArray {
            val out = ByteArray(65)
            out[0] = 0x04
            fixedLength(x, 32).copyInto(out, 1)
            fixedLength(y, 32).copyInto(out, 33)
            return out
        }

        private fun fixedLength(value: BigInteger, length: Int): ByteArray {
            val raw = value.toByteArray()
            val stripped = if (raw.size > length && raw[0].toInt() == 0) {
                raw.copyOfRange(raw.size - length, raw.size)
            } else {
                raw
            }
            val out = ByteArray(length)
            stripped.copyInto(out, length - stripped.size)
            return out
        }
    }
}
