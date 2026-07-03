// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import type { HybridObject } from 'react-native-nitro-modules'

// The Nitro wire contract for Signet: hardware-backed P-256 signing keys over the
// native Secure Enclave and Android Keystore cores. This is the code-generated
// transport surface; `../signet` wraps it in the idiomatic API. No method here
// carries key material or an export path. This surface is the non-interactive one:
// keys are silent and signing raises no prompt.

/** Hardware backing a key, reported as achieved and never assumed from the request. */
export type SecurityLevel = 'secureEnclave' | 'strongBox' | 'tee' | 'tpm' | 'software'

/** How the achieved level was determined; only `attested` is cryptographic proof. */
export type TierEvidence =
  | 'attested'
  | 'keyInfoReadback'
  | 'seTokenPresent'
  | 'inferred'
  | 'selfReportUnverified'

/** The presence check bound to a created key, reported in a tier report. */
export type AuthClass =
  | 'none'
  | 'biometricOnly'
  | 'biometricOrDeviceCredential'
  | 'deviceCredentialOnly'

/** A class in the tier partial order; `discreteSecure` outranks `trustedEnvironment`. */
export type HardwareClass = 'discreteSecure' | 'trustedEnvironment'

/** The tier-selection kind; `atLeast` carries its class in [KeySpec]. */
export type TierPolicyKind = 'strongest' | 'atLeast' | 'bestEffort'

/** Signature wire encoding: X9.62 DER or fixed 64-byte r||s. */
export type SignEncoding = 'der' | 'rawRS'

/** Public-key format: uncompressed X9.63 point or DER SubjectPublicKeyInfo. */
export type PublicKeyFormat = 'rawX962' | 'spki'

/** Attestation format: an Android key-attestation chain or none. */
export type AttestationFormat = 'androidKeyChain' | 'none'

/** A key-generation request. The achieved tier is read back from the created key. */
export interface KeySpec {
  alias: string
  tierPolicyKind: TierPolicyKind
  atLeastClass?: HardwareClass
  attestationChallenge?: ArrayBuffer
}

/** One report shape for every operation that reads a key's tier. */
export interface SecurityTierReport {
  achieved: SecurityLevel
  requestedKind?: TierPolicyKind
  requestedAtLeastClass?: HardwareClass
  meetsFloor: boolean
  evidence: TierEvidence
  authEnforced?: AuthClass
  invalidated: boolean
  schemaVersion: number
}

/** The result of generating a key: an opaque handle id and the created key's report. */
export interface GenerateResult {
  handleId: string
  report: SecurityTierReport
}

/** A public key in one of the pinned formats. No private-key surface exists. */
export interface PublicKeyData {
  format: PublicKeyFormat
  bytes: ArrayBuffer
}

/** Options for a signature. */
export interface SignOptions {
  encoding: SignEncoding
}

/** The attestation for a key: a chain of DER certs, or `none` with no chain. Produced, never verified. */
export interface AttestationResult {
  format: AttestationFormat
  chain?: ArrayBuffer[]
  schemaVersion: number
}

/**
 * The calls JS makes into the native core. An error crosses as a thrown native
 * error whose message is one of the closed error tokens; the idiomatic layer maps
 * it to a typed SignetError. The native side is not more trusted than JS; both run
 * in the same process and the only trust anchors are the hardware and a remote
 * attestation verifier this library never calls.
 */
export interface Signet extends HybridObject<{ ios: 'swift'; android: 'kotlin' }> {
  /** Generates a non-exportable P-256 key. Fails `keyAlreadyExists` on an existing alias. */
  generateKey(spec: KeySpec): GenerateResult
  /** Public key only; the private key has no export path. */
  getPublicKey(handleId: string, format: PublicKeyFormat): PublicKeyData
  /** Signs a 32-byte digest with no prompt. A wrong-length digest fails `invalidArgument`. */
  sign(handleId: string, digest: ArrayBuffer, options: SignOptions): Promise<ArrayBuffer>
  /** Attestation bound at generation; takes no call-time challenge. */
  getAttestation(handleId: string): AttestationResult
  /** Re-reads a key's tier; does not throw on an invalidated-but-present key. */
  getSecurityTier(handleId: string): SecurityTierReport
  /** Whether a key exists for the alias. */
  exists(alias: string): boolean
  /** Deletes the key for the alias. Idempotent: a missing alias is not an error. */
  deleteKey(alias: string): void
}
