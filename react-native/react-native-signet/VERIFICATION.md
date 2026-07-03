# Signet React Native binding verification

The React Native binding is a thin Nitro HybridObject over the `apple/` and
`android/` cores. It holds no key material and no cryptography; every
security-bearing operation runs in a core. A key is silent by default or carries a
presence check, and a gated key is signed by passing an `AuthPrompt` the native
side presents and authenticates directly. This records what is checked and what
needs a device.

## Checked by CI (ci-rn-lib)

`tsc` typechecks the whole TypeScript layer on every change to the binding or a
core it consumes: the Nitro spec (`src/specs/signet.nitro.ts`) and the idiomatic
API (`src/signet.ts`). This covers the `TierPolicy` union, the `AccessControl` and
`AuthPrompt` types, access-control key generation, the gated `sign` prompt
argument, the `SignetError` over the closed error set (with `authInProgress`,
`userCanceled`, `authFailed`, and `authContextRequired`), and the wire-to-typed
mapping. `biome` formats and lints the same files.

## Checked by nitrogen codegen

`nitrogen` regenerates the HybridObject bases (Swift, Kotlin, and the shared C++
JSI glue) from the spec, including the grown `sign` signature, the `AuthPrompt`
struct, and the `AuthRequirement` enum. The regenerated bases fix the exact
override signatures the native HybridObjects implement.

## Requires a device (device lane), not exercised here

- The native gated code is written against the core signatures, the confirmed
  Nitro `Promise` APIs, and the shipped Flutter binding's native-driven pattern,
  but is not compiled here: a Kotlin or Swift build needs the full example build
  (Gradle / Xcode), which is the device lane.
  - Android: the Kotlin HybridObject and the `android/` core (compiled in-module
    through a source set), the wire-to-core mapping, the enum-token casing, the
    `BiometricPrompt` gated sign hosted on the `ReactActivity`, and the
    `authContextRequired` path when no `FragmentActivity` is available.
  - iOS: the Swift HybridObject and its Secure Enclave-backed run. The Enclave is
    unavailable on the simulator, so a real device is required.
- The end-to-end gated runtime: generate a gated key, drive the biometric prompt,
  sign a digest, and confirm that a second concurrent gated sign fails
  `authInProgress`.
- The example gated demo in `SignetApp` and its local-dependency type wiring
  remain future work, as in the non-interactive binding.

## Inherited from the cores

The binding adds no cryptography and no gating mechanism. Signature encoding, the
DER-to-raw conversion, tier selection, the biometric-prompt gating (Android
`BiometricPrompt` over a `CryptoObject`-bound `Signature`, iOS `LAContext` on the
Secure Enclave), the serialized single-prompt rule (`authInProgress`), and the
closed error set are the cores', already exercised by the `apple/` and `android/`
unit tests and their verification ledgers.
