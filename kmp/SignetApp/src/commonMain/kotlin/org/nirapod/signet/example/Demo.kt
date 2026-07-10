// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

package org.nirapod.signet.example

import org.nirapod.signet.kmp.KeySpec
import org.nirapod.signet.kmp.PublicKey
import org.nirapod.signet.kmp.SignOptions
import org.nirapod.signet.kmp.Signet

/**
 * The end-to-end Signet flow for a demo host: the host constructs the platform
 * [Signet], this shared code exercises the non-gated surface and returns a
 * readable log. It is a consumer of the published contract only; it holds no key
 * material and has no export path.
 */
public object SignetDemo {
    public fun run(signet: Signet, alias: String): List<String> {
        val log = mutableListOf<String>()

        val result = signet.generateKey(KeySpec(alias))
        log += "generated ${result.handle.alias}: achieved=${result.report.achieved} evidence=${result.report.evidence}"

        val publicKey = signet.getPublicKey(result.handle, PublicKey.Format.rawX962)
        log += "public key: ${publicKey.bytes.size} bytes as ${publicKey.format}"

        val digest = ByteArray(32) { it.toByte() }
        val signature = signet.sign(result.handle, digest, SignOptions(SignOptions.Encoding.der))
        log += "signature: ${signature.size} bytes as der"

        val tier = signet.getSecurityTier(result.handle)
        log += "tier re-read: achieved=${tier.achieved} invalidated=${tier.invalidated}"

        val attestation = signet.getAttestation(result.handle)
        log += "attestation: format=${attestation.format} certs=${attestation.chain.size}"

        signet.delete(alias)
        log += "deleted $alias"

        return log
    }
}
