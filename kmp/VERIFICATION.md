<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Nirapod Labs -->

# KMP binding verification

What is proven in this repository, and what is deferred to the device farm.

## androidMain

The Android `actual` is a thin translation over the shipped `AndroidKeyStoreSigner`
core. It re-implements no key handling: every call forwards to the core, and the
only work in this layer is converting between the core's `xyz.nirapod.signet`
contract types and the KMP `xyz.nirapod.signet.kmp` types.

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

## appleMain and iosMain

Placeholder actuals. The Secure Enclave path over Security.framework lands with
the Apple work.
