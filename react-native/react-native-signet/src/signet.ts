// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import { NitroModules } from 'react-native-nitro-modules'
import type {
  AttestationFormat,
  AuthClass,
  HardwareClass,
  PublicKeyFormat,
  SecurityLevel,
  Signet as SignetSpec,
  SignEncoding,
  TierEvidence,
  TierPolicyKind,
} from './specs/signet.nitro'

export type {
  AttestationFormat,
  AuthClass,
  HardwareClass,
  PublicKeyFormat,
  SecurityLevel,
  SignEncoding,
  TierEvidence,
}

/**
 * Tier selection by class, never a concrete [SecurityLevel]. The achieved level is
 * reported in [SecurityTierReport.achieved]. Ordering is a partial order over
 * classes: `discreteSecure {secureEnclave, strongBox, tpm} > tee > software`.
 */
export type TierPolicy =
  | { readonly kind: 'strongest' }
  | { readonly kind: 'atLeast'; readonly floor: HardwareClass }
  | { readonly kind: 'bestEffort' }

/** The device's best hardware tier; fails `unavailableTier` if none, never software. */
export const strongest: TierPolicy = { kind: 'strongest' }
/** A hard floor by class; fails `unavailableTier` below the class. */
export const atLeast = (floor: HardwareClass): TierPolicy => ({ kind: 'atLeast', floor })
/** Never fails on tier where a software keystore exists; may return a weaker level. */
export const bestEffort: TierPolicy = { kind: 'bestEffort' }

/** An opaque handle to a generated key. Carries no key material. */
export interface KeyHandle {
  readonly id: string
}

/**
 * One report shape for every operation that reads a key's tier. [requested] and
 * [authEnforced] are undefined on a `getSecurityTier` re-read, where the policy is
 * not stored with the key and the platform may not read the access control back.
 */
export interface SecurityTierReport {
  readonly achieved: SecurityLevel
  readonly requested?: TierPolicy
  readonly meetsFloor: boolean
  readonly evidence: TierEvidence
  readonly authEnforced?: AuthClass
  readonly invalidated: boolean
  readonly schemaVersion: number
}

/** A public key in one of the pinned formats. The private key has no export path. */
export interface PublicKey {
  readonly format: PublicKeyFormat
  readonly bytes: ArrayBuffer
}

/** The attestation for a key: a certificate chain, or `none` with no chain. */
export interface AttestationResult {
  readonly format: AttestationFormat
  readonly chain?: ArrayBuffer[]
  readonly schemaVersion: number
}

/** Options for [Signet.sign]. */
export interface SignOptions {
  readonly encoding?: SignEncoding
}

/** The one closed error set; every binding raises these exact names (`userCanceled`, one `l`). */
export type SignetErrorCode =
  | 'unavailableTier'
  | 'userCanceled'
  | 'keyInvalidated'
  | 'authFailed'
  | 'authContextRequired'
  | 'notFound'
  | 'keyAlreadyExists'
  | 'tierMismatchOnExisting'
  | 'attestationUnsupported'
  | 'hardwareError'
  | 'unsupportedPlatform'
  | 'invalidArgument'
  | 'authInProgress'

const ERROR_CODES: readonly SignetErrorCode[] = [
  'unavailableTier',
  'userCanceled',
  'keyInvalidated',
  'authFailed',
  'authContextRequired',
  'notFound',
  'keyAlreadyExists',
  'tierMismatchOnExisting',
  'attestationUnsupported',
  'hardwareError',
  'unsupportedPlatform',
  'invalidArgument',
  'authInProgress',
]

/** The error every Signet operation throws, carrying one [SignetErrorCode]. */
export class SignetError extends Error {
  readonly code: SignetErrorCode

  constructor(code: SignetErrorCode, message?: string) {
    super(message ?? code)
    this.code = code
    this.name = 'SignetError'
  }
}

const native = NitroModules.createHybridObject<SignetSpec>('Signet')

/**
 * Hardware-backed P-256 signing keys via the native Secure Enclave and Android
 * Keystore cores. This surface is the non-interactive one: keys are silent and
 * signing raises no prompt. Every call marshals to the native core and rebuilds the
 * typed result; a core failure arrives as a [SignetError] over the closed set.
 */
export const Signet = {
  /**
   * Generates a non-exportable P-256 key at [alias]. [tierPolicy] selects by class
   * (default [strongest]); a hard policy below its floor fails `unavailableTier`,
   * while [bestEffort] never fails on tier and its report carries
   * `meetsFloor === false`. An existing alias fails `keyAlreadyExists`.
   */
  generateKey(options: {
    alias: string
    tierPolicy?: TierPolicy
    attestationChallenge?: ArrayBuffer
  }): { handle: KeyHandle; report: SecurityTierReport } {
    const policy = options.tierPolicy ?? strongest
    const result = guard(() =>
      native.generateKey({
        alias: options.alias,
        tierPolicyKind: policy.kind,
        atLeastClass: policy.kind === 'atLeast' ? policy.floor : undefined,
        attestationChallenge: options.attestationChallenge,
      }),
    )
    return { handle: { id: result.handleId }, report: reportFrom(result.report) }
  },

  /** Public key only. The private key has no export path. */
  getPublicKey(handle: KeyHandle, format: PublicKeyFormat = 'rawX962'): PublicKey {
    const result = guard(() => native.getPublicKey(handle.id, format))
    return { format: result.format, bytes: result.bytes }
  },

  /**
   * Signs a 32-byte digest (`NONEwithECDSA` / `ecdsaSignatureDigestX962SHA256`) with
   * no prompt. A wrong-length digest fails `invalidArgument` before any key access.
   */
  async sign(handle: KeyHandle, digest: ArrayBuffer, options?: SignOptions): Promise<ArrayBuffer> {
    return guardAsync(() =>
      native.sign(handle.id, digest, { encoding: options?.encoding ?? 'der' }),
    )
  },

  /** Attestation is produced, never verified. The challenge was bound at [generateKey]. */
  getAttestation(handle: KeyHandle): AttestationResult {
    const result = guard(() => native.getAttestation(handle.id))
    return { format: result.format, chain: result.chain, schemaVersion: result.schemaVersion }
  },

  /** Re-reads a key's tier. Does not throw on an invalidated-but-present key. */
  getSecurityTier(handle: KeyHandle): SecurityTierReport {
    return reportFrom(guard(() => native.getSecurityTier(handle.id)))
  },

  /** Whether a key exists for [alias]. */
  exists(alias: string): boolean {
    return guard(() => native.exists(alias))
  },

  /** Deletes the key for [alias]. Idempotent: a missing alias is not an error. */
  delete(alias: string): void {
    guard(() => native.deleteKey(alias))
  },
}

/** Runs a native call and maps a thrown native error's code to a [SignetError]. */
function guard<T>(call: () => T): T {
  try {
    return call()
  } catch (error) {
    throw signetErrorFrom(error)
  }
}

/** The async form of [guard], for the `Promise`-returning `sign`. */
async function guardAsync<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call()
  } catch (error) {
    throw signetErrorFrom(error)
  }
}

/**
 * Maps a thrown native error to a [SignetError]. The native core throws with a
 * message that is one of the closed error tokens; an unrecognized message maps to
 * `hardwareError`, so a new native code cannot masquerade as a typed one unnoticed.
 */
function signetErrorFrom(error: unknown): SignetError {
  if (error instanceof SignetError) {
    return error
  }
  const message = error instanceof Error ? error.message : String(error)
  // The native side throws the bare token; a Nitro sync call prefixes it with
  // "funcName: ", and a platform cause may be appended on later lines. Take the
  // first line's last colon-delimited word and match it exactly. An appended cause
  // then cannot collide with an earlier-declared token.
  const head = message.split('\n')[0] ?? message
  const token = head.slice(head.lastIndexOf(':') + 1).trim()
  const code = ERROR_CODES.find((candidate) => candidate === token)
  return new SignetError(code ?? 'hardwareError', message)
}

function reportFrom(report: {
  achieved: SecurityLevel
  requestedKind?: TierPolicyKind
  requestedAtLeastClass?: HardwareClass
  meetsFloor: boolean
  evidence: TierEvidence
  authEnforced?: AuthClass
  invalidated: boolean
  schemaVersion: number
}): SecurityTierReport {
  return {
    achieved: report.achieved,
    requested: tierPolicyFrom(report.requestedKind, report.requestedAtLeastClass),
    meetsFloor: report.meetsFloor,
    evidence: report.evidence,
    authEnforced: report.authEnforced,
    invalidated: report.invalidated,
    schemaVersion: report.schemaVersion,
  }
}

function tierPolicyFrom(
  kind: TierPolicyKind | undefined,
  atLeastClass: HardwareClass | undefined,
): TierPolicy | undefined {
  switch (kind) {
    case undefined:
      return undefined
    case 'strongest':
      return strongest
    case 'atLeast':
      return atLeast(atLeastClass as HardwareClass)
    case 'bestEffort':
      return bestEffort
  }
}
