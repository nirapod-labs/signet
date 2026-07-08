// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet

import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Flutter plugin entry point for the Signet Android binding.
 *
 * Registers the generated [SignetHostApi] and forwards every call to
 * [AndroidKeyStoreSigner] in the `android/` core. This class holds no policy and
 * no key material; the core is the only code that touches the Keystore. It is
 * [ActivityAware] so an auth-gated sign can host its biometric prompt on the
 * running activity.
 */
public class SignetPlugin : FlutterPlugin, ActivityAware {
    private var activity: FragmentActivity? = null
    private var impl: SignetHostApiImpl? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        val signer = AndroidKeyStoreSigner(binding.applicationContext)
        val hostApi = SignetHostApiImpl(signer) { activity }
        impl = hostApi
        SignetHostApi.setUp(binding.binaryMessenger, hostApi)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        SignetHostApi.setUp(binding.binaryMessenger, null)
        impl?.dispose()
        impl = null
    }

    // A biometric prompt needs a FragmentActivity to host it; the host app uses
    // FlutterFragmentActivity. A plain activity leaves this null, and a gated sign
    // then fails authContextRequired rather than crashing.
    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity as? FragmentActivity
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity as? FragmentActivity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onDetachedFromActivity() {
        activity = null
    }
}

/**
 * Bridges the generated host API to the core. Each non-signing call wraps the core
 * in [coded], which turns a [SignetException] into a Pigeon [FlutterError] carrying
 * the closed-set code. Signing keeps its own fail-closed mapping. Wire structs map
 * one-to-one to the core's canonical types; no policy decision is made in this
 * layer. Wire enums are the Pigeon-generated UPPER_SNAKE constants; the core enums
 * are camelCase.
 */
internal class SignetHostApiImpl(
    private val signer: AndroidKeyStoreSigner,
    private val activityProvider: () -> FragmentActivity?,
) : SignetHostApi {
    // Gated signing suspends on a main-thread biometric prompt; the core hops to
    // the main thread itself; this scope only needs to outlive the call.
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /** Cancels any in-flight gated sign when the engine detaches. */
    fun dispose() {
        scope.cancel()
    }

    override fun generateKey(spec: KeySpecWire): GenerateResultWire = coded {
        val (handle, report) = signer.generateKey(spec.toKeySpec())
        GenerateResultWire(handleId = handle.alias, report = report.toWire())
    }

    override fun getPublicKey(handleId: String, format: PublicKeyFormatWire): PublicKeyWire = coded {
        val publicKey = signer.getPublicKey(KeyHandle(handleId), format.toCore())
        PublicKeyWire(format = publicKey.format.toWire(), bytes = publicKey.bytes)
    }

    override fun sign(
        handleId: String,
        digest: ByteArray,
        options: SignOptionsWire,
        prompt: AuthPromptWire?,
        callback: (Result<ByteArray>) -> Unit,
    ) {
        if (prompt == null) {
            // Silent path: no prompt, the synchronous core sign.
            val outcome = try {
                Result.success(signer.sign(KeyHandle(handleId), digest, options.toCore()))
            } catch (failure: Exception) {
                signFailure(failure)
            }
            callback(outcome)
            return
        }
        // Gated path: a biometric prompt needs a FragmentActivity to host it.
        val activity = activityProvider()
        if (activity == null) {
            callback(
                Result.failure(SignetException(SignetErrorCode.authContextRequired).toFlutterError()),
            )
            return
        }
        val authContext = prompt.toAuthContext(activity)
        scope.launch {
            val outcome = try {
                Result.success(signer.sign(KeyHandle(handleId), digest, authContext, options.toCore()))
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (failure: Exception) {
                signFailure(failure)
            }
            callback(outcome)
        }
    }

    override fun getAttestation(handleId: String): AttestationResultWire = coded {
        signer.getAttestation(KeyHandle(handleId)).toWire()
    }

    override fun getSecurityTier(handleId: String): SecurityTierReportWire = coded {
        signer.getSecurityTier(KeyHandle(handleId)).toWire()
    }

    override fun exists(alias: String): Boolean = coded { signer.exists(alias) }

    override fun deleteKey(alias: String): Unit = coded { signer.delete(alias) }

    /**
     * Maps a signing failure to a closed-set [FlutterError]. A [SignetException]
     * carries its own code; anything else fails closed to `hardwareError`.
     */
    private fun signFailure(failure: Throwable): Result<ByteArray> = when (failure) {
        is SignetException -> Result.failure(failure.toFlutterError())
        else -> Result.failure(
            SignetException(SignetErrorCode.hardwareError, cause = failure).toFlutterError(),
        )
    }
}

/** Maps a [SignetException] to the Pigeon error carrying its closed-set code. */
private fun SignetException.toFlutterError(): FlutterError =
    FlutterError(code = code.name, message = message)

/** Runs a core call, translating a [SignetException] into a [FlutterError]. */
private inline fun <T> coded(block: () -> T): T =
    try {
        block()
    } catch (failure: SignetException) {
        throw failure.toFlutterError()
    }

// ---- wire -> core ----

private fun KeySpecWire.toKeySpec(): KeySpec = KeySpec(
    alias = alias,
    tierPolicy = coreTierPolicy(tierPolicyKind, atLeastClass),
    accessControl = AccessControlPolicy(
        authRequirement = authRequirement.toCore(),
        authValiditySeconds = authValiditySeconds?.toInt(),
        invalidateOnBiometricEnrollment = invalidateOnBiometricEnrollment,
    ),
    attestationChallenge = attestationChallenge,
)

private fun coreTierPolicy(
    kind: TierPolicyKindWire,
    atLeastClass: HardwareClassWire?,
): TierPolicy = when (kind) {
    TierPolicyKindWire.STRONGEST -> TierPolicy.Strongest
    TierPolicyKindWire.AT_LEAST -> TierPolicy.AtLeast(
        (atLeastClass ?: throw SignetException(SignetErrorCode.invalidArgument)).toCore(),
    )
}

private fun AuthRequirementWire.toCore(): AuthRequirement = when (this) {
    AuthRequirementWire.NONE -> AuthRequirement.none
    AuthRequirementWire.BIOMETRIC_ONLY -> AuthRequirement.biometricOnly
    AuthRequirementWire.BIOMETRIC_OR_DEVICE_CREDENTIAL -> AuthRequirement.biometricOrDeviceCredential
}

private fun AuthPromptWire.toAuthContext(activity: FragmentActivity): AuthContext = AuthContext(
    activity = activity,
    title = title,
    authRequirement = authRequirement.toCore(),
    subtitle = subtitle,
    negativeButtonText = negativeButtonText,
)

private fun HardwareClassWire.toCore(): HardwareClass = when (this) {
    HardwareClassWire.DISCRETE_SECURE -> HardwareClass.discreteSecure
    HardwareClassWire.TRUSTED_ENVIRONMENT -> HardwareClass.trustedEnvironment
}

private fun PublicKeyFormatWire.toCore(): PublicKey.Format = when (this) {
    PublicKeyFormatWire.RAW_X962 -> PublicKey.Format.rawX962
    PublicKeyFormatWire.SPKI -> PublicKey.Format.spki
}

private fun SignOptionsWire.toCore(): SignOptions = SignOptions(
    encoding = when (encoding) {
        SignEncodingWire.DER -> SignOptions.Encoding.der
        SignEncodingWire.RAW_RS -> SignOptions.Encoding.rawRS
    },
)

// ---- core -> wire ----

private fun SecurityTierReport.toWire(): SecurityTierReportWire {
    val (requestedKind, requestedAtLeastClass) = requestedToWire(requested)
    return SecurityTierReportWire(
        achieved = achieved.toWire(),
        requestedKind = requestedKind,
        requestedAtLeastClass = requestedAtLeastClass,
        evidence = evidence.toWire(),
        authEnforced = authEnforced?.toWire(),
        invalidated = invalidated,
        schemaVersion = schemaVersion.toLong(),
    )
}

private fun requestedToWire(
    policy: TierPolicy?,
): Pair<TierPolicyKindWire?, HardwareClassWire?> = when (policy) {
    null -> null to null
    TierPolicy.Strongest -> TierPolicyKindWire.STRONGEST to null
    is TierPolicy.AtLeast -> TierPolicyKindWire.AT_LEAST to policy.hardwareClass.toWire()
}

private fun AttestationResult.toWire(): AttestationResultWire = AttestationResultWire(
    format = when (format) {
        AttestationResult.Format.androidKeyChain -> AttestationFormatWire.ANDROID_KEY_CHAIN
        AttestationResult.Format.none -> AttestationFormatWire.NONE
    },
    chain = chain.ifEmpty { null },
    schemaVersion = schemaVersion.toLong(),
)

private fun SecurityLevel.toWire(): SecurityLevelWire = when (this) {
    SecurityLevel.strongBox -> SecurityLevelWire.STRONG_BOX
    SecurityLevel.tee -> SecurityLevelWire.TEE
}

private fun TierEvidence.toWire(): TierEvidenceWire = when (this) {
    TierEvidence.keyInfoReadback -> TierEvidenceWire.KEY_INFO_READBACK
}

private fun AuthClass.toWire(): AuthClassWire = when (this) {
    AuthClass.none -> AuthClassWire.NONE
    AuthClass.biometricOnly -> AuthClassWire.BIOMETRIC_ONLY
    AuthClass.biometricOrDeviceCredential -> AuthClassWire.BIOMETRIC_OR_DEVICE_CREDENTIAL
    AuthClass.deviceCredentialOnly -> AuthClassWire.DEVICE_CREDENTIAL_ONLY
}

private fun HardwareClass.toWire(): HardwareClassWire = when (this) {
    HardwareClass.discreteSecure -> HardwareClassWire.DISCRETE_SECURE
    HardwareClass.trustedEnvironment -> HardwareClassWire.TRUSTED_ENVIRONMENT
}

private fun PublicKey.Format.toWire(): PublicKeyFormatWire = when (this) {
    PublicKey.Format.rawX962 -> PublicKeyFormatWire.RAW_X962
    PublicKey.Format.spki -> PublicKeyFormatWire.SPKI
}
