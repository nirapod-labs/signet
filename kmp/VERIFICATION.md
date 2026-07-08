<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Nirapod Labs -->

# KMP binding verification

What is proven in this repository, and what is deferred to the device farm.

## androidMain

The Android `actual` is a thin translation over the shipped `AndroidKeyStoreSigner`
core. It re-implements no key handling: every call forwards to the core, and the
only work in this layer is converting between the core's `org.nirapod.signet`
contract types and the KMP `org.nirapod.signet.kmp` types.

Proven here (JVM host + compilation):

- The type translation is exact. `ConvertersTest` (`./gradlew testAndroidHostTest`)
  maps every `SecurityLevel`, `TierEvidence`, `AuthClass`, and `SignetErrorCode`
  entry by name and checks the `KeySpec` and `SecurityTierReport` field mappings.
  A by-name check fails if the two type sets ever drift apart.
- The whole surface compiles for every target (`make build-kmp`).

Inherited from the Android core (proven in the core's own suite):

- Real key generation (the StrongBox to TEE ladder with `KeyInfo` read-back tier),
  signing over a 32-byte digest, attestation production, lifecycle, and the closed
  error set.

Deferred to the device farm (real hardware, not settleable here):

- End-to-end generate, sign, and report through the KMP `Signet(context)` surface
  on an emulator and a device. The core's key operations are already proven; this
  confirms the KMP wiring end to end.
- The `strongBox` tier and a real `androidKeyChain` attestation chain, which need
  StrongBox and attested hardware.

## appleMain

The Apple `actual` re-implements the Secure Enclave path over Security.framework
in Kotlin/Native, faithful to the Apple Swift core. One `actual` serves the iOS
and macOS targets.

Proven here (compilation and the `SecureEnclaveTest` macOS host suite):

- Every Apple target compiles: `iosArm64`, `iosSimulatorArm64`, and `macosArm64`.
  The Security.framework bindings resolve on each.
- The signature codec is exact. `derToRawRS` maps a canonical signature, strips
  positive-integer padding, left-pads short components, and rejects malformed DER
  and over-length components. The SPKI wrap prepends the fixed P-256 header.
- The policy mapping is exact. The access-control flags and the reported
  `AuthClass` match each `AuthRequirement`, and the creation-failure codes map to
  the closed error set.
- The Security.framework binding links and signs. A transient host P-256 key runs
  the real `SecKeyCreateSignature` path through the CFData bridging to a 64-byte
  `r || s`, and exports a 65-byte X9.63 public key. This is a host software key,
  not the Enclave, and it proves the binding, the algorithm selector, and the CF
  memory handling against real Security.framework.

Deferred to the device farm (real Secure Enclave hardware):

- End-to-end generate, sign, tier, and attestation through `Signet()` on a device.
  Enclave key creation, keychain persistence (`exists`, `delete`,
  `getSecurityTier`), the `secureEnclave` tier with `seTokenPresent` evidence, and
  non-export need the Enclave and a signed app with the keychain entitlement, which
  a CI host and an unsigned test binary do not provide.
- The iOS simulator test lanes stay excluded pending a Kotlin/Native and Xcode
  toolchain fix. The macOS host lane covers the shared Apple code in the meantime.

## Auth-gated sign

The gated `sign` presents a biometric prompt and suspends until the user responds.
The live prompt-and-sign is device-gated by a real enrolled biometric; the host
suite proves the platform-independent logic.

Proven here (host):

- `SignGate` rejects a concurrent gated sign with `authInProgress` and re-admits
  after exit (`signGateRejectsConcurrentEntry`).
- `mapGatedSignFailure` maps the LocalAuthentication codes to the closed error set
  (`mapGatedSignFailureMapsAuthCodes`); `gatedReason` composes the prompt line.
- The whole surface compiles: the appleMain gated sign on the Apple targets and the
  androidMain delegation on the Android host.

Inherited from the cores:

- The Android core drives the gated sign through `BiometricPrompt`; the KMP
  androidMain delegates to it. The appleMain re-implements the Apple core's
  LAContext path in Kotlin/Native.

Deferred to the device farm:

- The end-to-end gated sign through `Signet.sign(..., authContext, ...)` with a real
  prompt: the biometric prompt, the authenticated signature, and the cancel and
  failure error paths.

watchOS is not a Signet target: its LocalAuthentication has no `localizedReason`
and no biometry error codes, so it cannot present the gated prompt.

## Conformance

KMP conformance is proven here by the binding's own suites, the Dart and RN
precedent. `ContractTest` (commonTest) asserts the closed error set against
`conformance/errors.json` (thirteen names, the `userCanceled` spelling), the tier
partial order (`tpm` not below `tee`, `software` below every hardware class), the
closed-set sizes, and the shape defaults. `ConvertersTest` (androidHostTest) checks
the android-core translation both directions.

Populating `conformance/vectors.json` with golden signature and attestation vectors
and flipping `conformance/behaviors.yaml` from `pending` to `verified` across the
Dart, TypeScript, Kotlin, and Swift runners is the cross-language completion, which
depends on all four bindings. The polyglot kotlin runner stays a pending-consistent
stub until then; no behavior is answered `pass` while it is `pending`.

## Example

`kmp/SignetApp` composite-builds this library and drives its non-gated surface from
`commonMain` (`SignetDemo`: generate, public key, sign, tier, attestation, delete).
It compiles against `iosArm64`, `iosSimulatorArm64`, and `macosArm64`, proving the
contract is importable and usable from a separate Kotlin Multiplatform project. An
on-device host and an Android application target are future work.
