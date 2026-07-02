// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package xyz.nirapod.signet

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Instrumented battery for the real Android Keystore. Runs on a device or
 * emulator, not in ci-android (unit-only) - see android/VERIFICATION.md. It
 * exercises the silent mechanisms end-to-end against a live Keystore. The
 * biometric-gated sign flow needs an enrolled credential and a UI lane and is a
 * documented device-lane check, not asserted here.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeyStoreSignerInstrumentedTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val signer = AndroidKeyStoreSigner(context)
    private val alias = "signet-instrumented-test-key"

    @After
    fun cleanup() {
        signer.delete(alias)
    }

    @Test
    fun generatesAKeyInHardwareAndReadsBackTheTier() {
        val (handle, report) = signer.generateKey(KeySpec(alias, tierPolicy = TierPolicy.BestEffort))
        assertEquals(alias, handle.alias)
        assertNotNull(report.achieved)
        val reread = signer.getSecurityTier(handle)
        assertEquals(report.achieved, reread.achieved)
        assertNull(reread.requested) // the policy is not stored with the key
    }

    @Test
    fun theGeneratedPublicKeyIsAValidUncompressedPoint() {
        val (handle, _) = signer.generateKey(KeySpec(alias, tierPolicy = TierPolicy.BestEffort))
        val publicKey = signer.getPublicKey(handle)
        assertEquals(PublicKey.Format.rawX962, publicKey.format)
        assertEquals(65, publicKey.bytes.size)
        assertEquals(0x04.toByte(), publicKey.bytes[0])
    }

    @Test
    fun thePrivateKeyIsNotExportable() {
        signer.generateKey(KeySpec(alias, tierPolicy = TierPolicy.BestEffort))
        // The Keystore never releases private-key material: getEncoded is null.
        assertNull(signer.loadPrivateKey(alias).encoded)
    }

    @Test
    fun aSilentSignatureVerifiesAgainstThePublicKey() {
        val (handle, _) = signer.generateKey(KeySpec(alias, tierPolicy = TierPolicy.BestEffort))
        val digest = ByteArray(32) { it.toByte() }
        val der = signer.sign(handle, digest)
        val verifier = Signature.getInstance("NONEwithECDSA")
        verifier.initVerify(publicKeyFromSpki(signer.getPublicKey(handle, PublicKey.Format.spki).bytes))
        verifier.update(digest)
        assertTrue(verifier.verify(der))
    }

    @Test
    fun aRawEncodedSignatureIs64Bytes() {
        val (handle, _) = signer.generateKey(KeySpec(alias, tierPolicy = TierPolicy.BestEffort))
        val raw = signer.sign(handle, ByteArray(32) { 0x11 }, SignOptions(SignOptions.Encoding.rawRS))
        assertEquals(64, raw.size)
    }

    @Test
    fun aChallengeProducesAnAttestationChain() {
        val (handle, _) = signer.generateKey(
            KeySpec(
                alias,
                tierPolicy = TierPolicy.BestEffort,
                attestationChallenge = ByteArray(16) { 0x42 },
            ),
        )
        val attestation = signer.getAttestation(handle)
        assertEquals(AttestationResult.Format.androidKeyChain, attestation.format)
        assertTrue(attestation.chain.isNotEmpty())
    }

    @Test
    fun noChallengeYieldsNoAttestation() {
        val (handle, _) = signer.generateKey(KeySpec(alias, tierPolicy = TierPolicy.BestEffort))
        val attestation = signer.getAttestation(handle)
        assertEquals(AttestationResult.Format.none, attestation.format)
        assertTrue(attestation.chain.isEmpty())
    }

    @Test
    fun regeneratingAnExistingAliasFails() {
        signer.generateKey(KeySpec(alias, tierPolicy = TierPolicy.BestEffort))
        val error = try {
            signer.generateKey(KeySpec(alias, tierPolicy = TierPolicy.BestEffort))
            null
        } catch (thrown: SignetException) {
            thrown
        }
        assertEquals(SignetErrorCode.keyAlreadyExists, error?.code)
    }

    @Test
    fun deleteIsIdempotent() {
        signer.generateKey(KeySpec(alias, tierPolicy = TierPolicy.BestEffort))
        signer.delete(alias)
        signer.delete(alias) // a second delete is a no-op, not an error
        assertFalse(signer.exists(alias))
    }

    private fun publicKeyFromSpki(bytes: ByteArray): java.security.PublicKey =
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes))
}
