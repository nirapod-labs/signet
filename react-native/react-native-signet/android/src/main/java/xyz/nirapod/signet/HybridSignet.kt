// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

import com.margelo.nitro.NitroModules
import com.margelo.nitro.core.ArrayBuffer
import com.margelo.nitro.core.Promise
import com.margelo.nitro.signet.HybridSignetSpec
import com.margelo.nitro.signet.AttestationFormat as WireAttestationFormat
import com.margelo.nitro.signet.AttestationResult as WireAttestationResult
import com.margelo.nitro.signet.GenerateResult as WireGenerateResult
import com.margelo.nitro.signet.HardwareClass as WireHardwareClass
import com.margelo.nitro.signet.KeySpec as WireKeySpec
import com.margelo.nitro.signet.PublicKeyData as WirePublicKeyData
import com.margelo.nitro.signet.PublicKeyFormat as WirePublicKeyFormat
import com.margelo.nitro.signet.SecurityLevel as WireSecurityLevel
import com.margelo.nitro.signet.SecurityTierReport as WireSecurityTierReport
import com.margelo.nitro.signet.SignEncoding as WireSignEncoding
import com.margelo.nitro.signet.SignOptions as WireSignOptions
import com.margelo.nitro.signet.TierEvidence as WireTierEvidence
import com.margelo.nitro.signet.TierPolicyKind as WireTierPolicyKind

/**
 * The Nitro HybridObject for Android. Subclasses the generated [HybridSignetSpec]
 * and forwards every call to [AndroidKeyStoreSigner] in the `android/` core. It
 * holds no policy and no key material; the core is the only code that touches the
 * Keystore. This is the non-interactive surface: keys are silent and signing raises
 * no prompt.
 *
 * The core types are unqualified (same package); the generated Nitro wire types are
 * imported with a `Wire` prefix. Wire enums are the Nitro UPPER_CASE constants; the
 * core enums are camelCase.
 */
class HybridSignet : HybridSignetSpec() {
  private val signer: AndroidKeyStoreSigner by lazy {
    val context = NitroModules.applicationContext
      ?: throw SignetException(SignetErrorCode.hardwareError, "no application context")
    AndroidKeyStoreSigner(context)
  }

  override fun generateKey(spec: WireKeySpec): WireGenerateResult = coded {
    val (handle, report) = signer.generateKey(spec.toCore())
    WireGenerateResult(handleId = handle.alias, report = report.toWire())
  }

  override fun getPublicKey(handleId: String, format: WirePublicKeyFormat): WirePublicKeyData = coded {
    val publicKey = signer.getPublicKey(KeyHandle(handleId), format.toCore())
    WirePublicKeyData(format = publicKey.format.toWire(), bytes = ArrayBuffer.copy(publicKey.bytes))
  }

  override fun sign(handleId: String, digest: ArrayBuffer, options: WireSignOptions): Promise<ArrayBuffer> {
    // Copy the digest out unconditionally before the async hop. toByteArray can
    // alias a CPU-backed buffer; an explicit copy prevents a mutation between here
    // and the background sign.
    val digestBytes = ArrayBuffer.copy(digest).toByteArray()
    val coreOptions = SignOptions(encoding = options.encoding.toCore())
    return Promise.async {
      coded {
        val signature = signer.sign(KeyHandle(handleId), digestBytes, coreOptions)
        ArrayBuffer.copy(signature)
      }
    }
  }

  override fun getAttestation(handleId: String): WireAttestationResult = coded {
    signer.getAttestation(KeyHandle(handleId)).toWire()
  }

  override fun getSecurityTier(handleId: String): WireSecurityTierReport = coded {
    signer.getSecurityTier(KeyHandle(handleId)).toWire()
  }

  override fun exists(alias: String): Boolean = coded { signer.exists(alias) }

  override fun deleteKey(alias: String) {
    coded { signer.delete(alias) }
  }
}

// ---- error mapping ----

/**
 * Runs a core call, rethrowing a [SignetException] as an exception whose message is
 * the closed-set token. Nitro has no structured error-code channel, so the token
 * travels in the message; the idiomatic TS layer maps it back. A non-[SignetException]
 * fails closed to `hardwareError`.
 */
private inline fun <T> coded(block: () -> T): T =
  try {
    block()
  } catch (failure: SignetException) {
    throw RuntimeException(failure.code.name, failure)
  } catch (failure: Throwable) {
    throw RuntimeException(SignetErrorCode.hardwareError.name, failure)
  }

// ---- wire -> core ----

private fun WireKeySpec.toCore(): KeySpec = KeySpec(
  alias = alias,
  tierPolicy = when (tierPolicyKind) {
    WireTierPolicyKind.STRONGEST -> TierPolicy.Strongest
    WireTierPolicyKind.ATLEAST -> TierPolicy.AtLeast(
      (atLeastClass ?: throw SignetException(SignetErrorCode.invalidArgument)).toCore(),
    )
    WireTierPolicyKind.BESTEFFORT -> TierPolicy.BestEffort
  },
  accessControl = AccessControlPolicy.None,
  attestationChallenge = attestationChallenge?.toByteArray(),
)

private fun WireHardwareClass.toCore(): HardwareClass = when (this) {
  WireHardwareClass.DISCRETESECURE -> HardwareClass.discreteSecure
  WireHardwareClass.TRUSTEDENVIRONMENT -> HardwareClass.trustedEnvironment
}

private fun WirePublicKeyFormat.toCore(): PublicKey.Format = when (this) {
  WirePublicKeyFormat.RAWX962 -> PublicKey.Format.rawX962
  WirePublicKeyFormat.SPKI -> PublicKey.Format.spki
}

private fun WireSignEncoding.toCore(): SignOptions.Encoding = when (this) {
  WireSignEncoding.DER -> SignOptions.Encoding.der
  WireSignEncoding.RAWRS -> SignOptions.Encoding.rawRS
}

// ---- core -> wire ----

private fun SecurityTierReport.toWire(): WireSecurityTierReport {
  val (requestedKind, requestedAtLeastClass) = requestedToWire(requested)
  return WireSecurityTierReport(
    achieved = achieved.toWire(),
    requestedKind = requestedKind,
    requestedAtLeastClass = requestedAtLeastClass,
    meetsFloor = meetsFloor,
    evidence = evidence.toWire(),
    authEnforced = authEnforced?.toWire(),
    invalidated = invalidated,
    schemaVersion = schemaVersion.toDouble(),
  )
}

private fun requestedToWire(policy: TierPolicy?): Pair<WireTierPolicyKind?, WireHardwareClass?> = when (policy) {
  null -> null to null
  TierPolicy.Strongest -> WireTierPolicyKind.STRONGEST to null
  is TierPolicy.AtLeast -> WireTierPolicyKind.ATLEAST to policy.hardwareClass.toWire()
  TierPolicy.BestEffort -> WireTierPolicyKind.BESTEFFORT to null
}

private fun AttestationResult.toWire(): WireAttestationResult = WireAttestationResult(
  format = when (format) {
    AttestationResult.Format.androidKeyChain -> WireAttestationFormat.ANDROIDKEYCHAIN
    AttestationResult.Format.none -> WireAttestationFormat.NONE
  },
  chain = chain.ifEmpty { null }?.map { ArrayBuffer.copy(it) }?.toTypedArray(),
  schemaVersion = schemaVersion.toDouble(),
)

private fun SecurityLevel.toWire(): WireSecurityLevel = when (this) {
  SecurityLevel.secureEnclave -> WireSecurityLevel.SECUREENCLAVE
  SecurityLevel.strongBox -> WireSecurityLevel.STRONGBOX
  SecurityLevel.tee -> WireSecurityLevel.TEE
  SecurityLevel.tpm -> WireSecurityLevel.TPM
  SecurityLevel.software -> WireSecurityLevel.SOFTWARE
}

private fun TierEvidence.toWire(): WireTierEvidence = when (this) {
  TierEvidence.attested -> WireTierEvidence.ATTESTED
  TierEvidence.keyInfoReadback -> WireTierEvidence.KEYINFOREADBACK
  TierEvidence.seTokenPresent -> WireTierEvidence.SETOKENPRESENT
  TierEvidence.inferred -> WireTierEvidence.INFERRED
  TierEvidence.selfReportUnverified -> WireTierEvidence.SELFREPORTUNVERIFIED
}

private fun AuthClass.toWire(): com.margelo.nitro.signet.AuthClass = when (this) {
  AuthClass.none -> com.margelo.nitro.signet.AuthClass.NONE
  AuthClass.biometricOnly -> com.margelo.nitro.signet.AuthClass.BIOMETRICONLY
  AuthClass.biometricOrDeviceCredential -> com.margelo.nitro.signet.AuthClass.BIOMETRICORDEVICECREDENTIAL
  AuthClass.deviceCredentialOnly -> com.margelo.nitro.signet.AuthClass.DEVICECREDENTIALONLY
}

private fun HardwareClass.toWire(): WireHardwareClass = when (this) {
  HardwareClass.discreteSecure -> WireHardwareClass.DISCRETESECURE
  HardwareClass.trustedEnvironment -> WireHardwareClass.TRUSTEDENVIRONMENT
}

private fun PublicKey.Format.toWire(): WirePublicKeyFormat = when (this) {
  PublicKey.Format.rawX962 -> WirePublicKeyFormat.RAWX962
  PublicKey.Format.spki -> WirePublicKeyFormat.SPKI
}
