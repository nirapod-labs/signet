// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

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
    private val signGate = AuthSignGate()

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

    /**
     * Signs a 32-byte digest and encodes it per [options]. A wrong-length digest
     * is rejected with `invalidArgument` before any key access. This is the
     * silent path: it presents no authentication prompt. A key whose presence
     * check is not currently satisfied surfaces as `hardwareError`.
     *
     * @throws SignetException `invalidArgument` if the digest is not 32 bytes;
     *   `notFound` if no key exists; `keyInvalidated` if biometric re-enrollment
     *   invalidated the key; `hardwareError` on any other signing failure.
     */
    public fun sign(
        handle: KeyHandle,
        digest: ByteArray,
        options: SignOptions = SignOptions(),
    ): ByteArray {
        requireDigest32(digest)
        val privateKey = loadPrivateKey(handle.alias)
        val der = try {
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initSign(privateKey)
            signature.update(digest)
            signature.sign()
        } catch (invalidated: KeyPermanentlyInvalidatedException) {
            throw SignetException(SignetErrorCode.keyInvalidated, cause = invalidated)
        } catch (failure: Exception) {
            throw SignetException(SignetErrorCode.hardwareError, cause = failure)
        }
        return when (options.encoding) {
            SignOptions.Encoding.der -> der
            SignOptions.Encoding.rawRS ->
                derToRawSignature(der) ?: throw SignetException(SignetErrorCode.hardwareError)
        }
    }

    /**
     * Signs a 32-byte digest with an auth-gated key, driving a biometric prompt
     * through [authContext] and suspending until the user responds. Auth-gated
     * signing is serialized: a second call issued while a prompt is still
     * outstanding is rejected with `authInProgress`. The digest guard and the
     * [options] encoding match the silent [sign].
     *
     * @throws SignetException `invalidArgument` if the digest is not 32 bytes;
     *   `authInProgress` if a gated sign is already in progress; `notFound` if no
     *   key exists; `keyInvalidated` if biometric re-enrollment invalidated the
     *   key; `userCanceled` if the user dismissed the prompt; `authFailed` if
     *   authentication failed; `authContextRequired` if the prompt cannot be
     *   presented; `hardwareError` on any other signing failure.
     */
    public suspend fun sign(
        handle: KeyHandle,
        digest: ByteArray,
        authContext: AuthContext,
        options: SignOptions = SignOptions(),
    ): ByteArray {
        requireDigest32(digest)
        if (!signGate.tryEnter()) throw SignetException(SignetErrorCode.authInProgress)
        try {
            val privateKey = loadPrivateKey(handle.alias)
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            try {
                signature.initSign(privateKey)
            } catch (invalidated: KeyPermanentlyInvalidatedException) {
                throw SignetException(SignetErrorCode.keyInvalidated, cause = invalidated)
            } catch (failure: Exception) {
                throw SignetException(SignetErrorCode.hardwareError, cause = failure)
            }
            val authenticated = authenticate(authContext, signature)
            val der = try {
                authenticated.update(digest)
                authenticated.sign()
            } catch (invalidated: KeyPermanentlyInvalidatedException) {
                throw SignetException(SignetErrorCode.keyInvalidated, cause = invalidated)
            } catch (failure: Exception) {
                throw SignetException(SignetErrorCode.hardwareError, cause = failure)
            }
            return when (options.encoding) {
                SignOptions.Encoding.der -> der
                SignOptions.Encoding.rawRS ->
                    derToRawSignature(der) ?: throw SignetException(SignetErrorCode.hardwareError)
            }
        } finally {
            signGate.exit()
        }
    }

    /**
     * Presents the biometric prompt bound to [signature] and suspends until the
     * user responds, returning the authenticated [Signature]. Runs on the main
     * thread, as `BiometricPrompt` requires. A dismissed prompt maps to
     * `userCanceled`, a lockout to `authFailed`, an unpresentable prompt to
     * `authContextRequired`, and anything else to `hardwareError`.
     */
    private suspend fun authenticate(
        authContext: AuthContext,
        signature: Signature,
    ): Signature = withContext(Dispatchers.Main.immediate) {
        suspendCancellableCoroutine<Signature> { continuation ->
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authenticated = result.cryptoObject?.signature
                    if (authenticated != null) {
                        continuation.resume(authenticated)
                    } else {
                        continuation.resumeWithException(SignetException(SignetErrorCode.hardwareError))
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    continuation.resumeWithException(authError(code))
                }
            }
            val prompt = BiometricPrompt(
                authContext.activity,
                ContextCompat.getMainExecutor(authContext.activity),
                callback,
            )
            continuation.invokeOnCancellation { prompt.cancelAuthentication() }
            try {
                prompt.authenticate(
                    buildPromptInfo(authContext),
                    BiometricPrompt.CryptoObject(signature),
                )
            } catch (presentation: IllegalStateException) {
                // The activity is not in a state that can host the prompt.
                continuation.resumeWithException(
                    SignetException(SignetErrorCode.authContextRequired, cause = presentation),
                )
            } catch (presentation: IllegalArgumentException) {
                // The prompt configuration is not presentable on this device.
                continuation.resumeWithException(
                    SignetException(SignetErrorCode.authContextRequired, cause = presentation),
                )
            } catch (failure: Exception) {
                continuation.resumeWithException(
                    SignetException(SignetErrorCode.hardwareError, cause = failure),
                )
            }
        }
    }

    /**
     * Builds the prompt. The allowed authenticators follow the key's declared
     * [AuthContext.authRequirement]: a device-credential-capable key allows the
     * device credential on API 30+ (where a crypto-bound device credential is
     * supported) and is biometric-only below that; a biometric-only key shows the
     * caller's negative button.
     */
    private fun buildPromptInfo(authContext: AuthContext): BiometricPrompt.PromptInfo {
        val builder = BiometricPrompt.PromptInfo.Builder().setTitle(authContext.title)
        authContext.subtitle?.let { builder.setSubtitle(it) }
        val allowsDeviceCredential =
            authContext.authRequirement == AuthRequirement.biometricOrDeviceCredential &&
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
        if (allowsDeviceCredential) {
            builder.setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
        } else {
            builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            builder.setNegativeButtonText(authContext.negativeButtonText)
        }
        return builder.build()
    }

    /** Maps a `BiometricPrompt` terminal error code to the closed error set. */
    private fun authError(code: Int): SignetException = SignetException(
        when (code) {
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            BiometricPrompt.ERROR_CANCELED -> SignetErrorCode.userCanceled
            BiometricPrompt.ERROR_LOCKOUT,
            BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> SignetErrorCode.authFailed
            else -> SignetErrorCode.hardwareError
        },
    )

    /**
     * Re-reads the tier of an existing key from its [KeyInfo]. `requested` comes
     * back null: the policy is not stored with the key. Unlike Apple, Android can
     * read the created key's auth requirement back from [KeyInfo], and
     * `authEnforced` is populated here rather than null. `invalidated` is
     * best-effort false; the authoritative invalidation signal is `keyInvalidated`
     * on `sign`. `meetsFloor` reports whether the key is in hardware at all, with
     * no stored policy to check against.
     *
     * @throws SignetException `notFound` if no key exists for the alias.
     */
    public fun getSecurityTier(handle: KeyHandle): SecurityTierReport {
        val privateKey = loadPrivateKey(handle.alias)
        val keyInfo = keyInfoOf(privateKey)
        val achieved = securityLevelReRead(keyInfo)
        return SecurityTierReport(
            achieved = achieved,
            requested = null,
            meetsFloor = achieved.hardwareClass != null,
            evidence = if (achieved == SecurityLevel.software) {
                TierEvidence.selfReportUnverified
            } else {
                TierEvidence.keyInfoReadback
            },
            authEnforced = authClass(keyInfo),
            invalidated = false,
        )
    }

    /**
     * Returns the attestation bound to a key at generation. A key created with an
     * attestation challenge carries a hardware key-attestation chain
     * (`androidKeyChain`); a key created without one returns `none` with an empty
     * chain. There is no call-time challenge. The chain is returned as produced
     * and is never verified here.
     *
     * @throws SignetException `notFound` if no key exists for the alias.
     */
    public fun getAttestation(handle: KeyHandle): AttestationResult {
        val store = keyStore()
        val entryAlias = keystoreAlias(handle.alias)
        if (!store.containsAlias(entryAlias)) throw SignetException(SignetErrorCode.notFound)
        val chain = store.getCertificateChain(entryAlias)
        if (chain == null || chain.isEmpty()) {
            return AttestationResult(AttestationResult.Format.none)
        }
        val leaf = chain[0] as? X509Certificate
            ?: return AttestationResult(AttestationResult.Format.none)
        val attested = leaf.getExtensionValue(KEY_ATTESTATION_OID) != null
        return if (attested) {
            AttestationResult(AttestationResult.Format.androidKeyChain, chain.map { it.encoded })
        } else {
            AttestationResult(AttestationResult.Format.none)
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
     * The achieved tier read back from an existing key, with no creation-time
     * StrongBox signal. On API 31+ the Keystore reports the level directly; below
     * that, `isInsideSecureHardware` distinguishes the TEE from software but
     * cannot prove StrongBox: a StrongBox key reads back as `tee`. `generateKey`
     * reports the StrongBox level at creation, where the creation signal is
     * available.
     */
    private fun securityLevelReRead(keyInfo: KeyInfo): SecurityLevel {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return securityLevelFromCode(keyInfo.securityLevel)
        }
        @Suppress("DEPRECATION")
        return if (keyInfo.isInsideSecureHardware) SecurityLevel.tee else SecurityLevel.software
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

        /** JCA algorithm for signing a pre-computed digest with an EC key. */
        private const val SIGNATURE_ALGORITHM = "NONEwithECDSA"

        /** OID of the Android key-attestation certificate extension. */
        private const val KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

        /**
         * Rejects a digest that is not exactly 32 bytes with `invalidArgument`,
         * before any key access. A P-256 signature is over a 32-byte digest; a
         * wrong-length input is a caller error, never a hardware failure.
         */
        internal fun requireDigest32(digest: ByteArray) {
            if (digest.size != 32) throw SignetException(SignetErrorCode.invalidArgument)
        }

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

        /**
         * Converts a DER ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`) to
         * the fixed 64-byte `r || s` form, each a 32-byte big-endian integer.
         * Returns null if the DER is malformed or a component exceeds 32 bytes;
         * `sign` maps that to `hardwareError`. Structurally identical to the Apple
         * core's `derToRawRS`: both decoders reject the same inputs.
         */
        internal fun derToRawSignature(der: ByteArray): ByteArray? {
            if (der.size < 2 || (der[0].toInt() and 0xFF) != 0x30 || (der[1].toInt() and 0x80) != 0) {
                return null
            }
            val seqLen = der[1].toInt() and 0xFF
            if (2 + seqLen != der.size) return null
            val r = readDerInteger(der, 2) ?: return null
            val s = readDerInteger(der, r.second) ?: return null
            if (s.second != der.size) return null
            val r32 = leftPad32(r.first) ?: return null
            val s32 = leftPad32(s.first) ?: return null
            return r32 + s32
        }

        /**
         * Reads one DER INTEGER at [start], returning its big-endian bytes with
         * any positive-padding `0x00` stripped, paired with the index past it.
         * Null if the tag, length, or bounds are malformed.
         */
        private fun readDerInteger(bytes: ByteArray, start: Int): Pair<ByteArray, Int>? {
            if (start + 1 >= bytes.size) return null
            if ((bytes[start].toInt() and 0xFF) != 0x02) return null
            if ((bytes[start + 1].toInt() and 0x80) != 0) return null
            val len = bytes[start + 1].toInt() and 0xFF
            val valueStart = start + 2
            if (len <= 0 || valueStart + len > bytes.size) return null
            val end = valueStart + len
            var offset = valueStart
            while (end - offset > 1 && bytes[offset].toInt() == 0) offset++
            return bytes.copyOfRange(offset, end) to end
        }

        /** Left-pads a big-endian integer to 32 bytes. Null if it exceeds 32. */
        private fun leftPad32(value: ByteArray): ByteArray? {
            if (value.size > 32) return null
            val out = ByteArray(32)
            value.copyInto(out, 32 - value.size)
            return out
        }
    }
}
