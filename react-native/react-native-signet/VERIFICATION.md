# Signet React Native binding verification

The React Native binding is a thin Nitro HybridObject over the `apple/` and
`android/` cores. It holds no key material and no cryptography; every
security-bearing operation runs in a core. This records what is checked and what
needs a device.

## Checked by CI (ci-rn-lib)

`tsc` typechecks the TypeScript layer on every change to the binding or a core it
consumes: the Nitro spec (`src/specs/signet.nitro.ts`), and the idiomatic API
(`src/signet.ts`) with its `TierPolicy` union, its `SignetError` over the closed
error set, and the wire-to-typed mapping.

## Checked by a local build

- `nitrogen` generates the HybridObject bases (Swift, Kotlin, and the shared C++
  JSI glue) from the spec.
- Android: `:react-native-signet:compileDebugKotlin` compiled the Kotlin
  HybridObject and the `android/` core (compiled in-module through a source set),
  together with the Nitro C++ adapter, in an `expo run:android` build against a
  real device. This catches the wire-to-core mapping, the enum-token casing, and
  the constructor shapes.

## Requires a device (device lane), not exercised here

- The end-to-end runtime against the real Android Keystore through the example
  app: generate (best effort), read the public key, sign a digest, delete.
- The iOS Swift HybridObject: written, not compiled here. Its compile and its
  Secure Enclave-backed run are the device lane; the Secure Enclave is
  unavailable on the simulator, so a real device is required.

## Inherited from the cores

The binding adds no cryptography. Signature encoding, the DER-to-raw conversion,
tier selection, and the closed error set are the cores', already exercised by the
`apple/` and `android/` unit tests and their verification ledgers.
