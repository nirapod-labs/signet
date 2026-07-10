# Android core verification

The Android core's security claims rest on the platform Keystore. This records
which are checked by ci-android (JVM unit tests, no device), which are written
as an instrumented battery that runs on a device or emulator, and which need
physical secure hardware or a UI lane that neither can provide.

## Checked in ci-android (JVM unit tests, no device)

The pure logic behind the store's guarantees runs green on every build,
`./gradlew testDebugUnitTest`, with no Keystore:

- The tier partial order and the `KeyInfo.getSecurityLevel` mapping: `strongest`
  accepts only the platform's best tier, a StrongBox fall-back to the TEE fails
  closed, and a software-backed or unknown Keystore level throws rather than
  returning a software tier (`SecurityTierTest`).
- The DER ECDSA to raw `r || s` decoder, over fixed and malformed vectors
  (`DerSignatureTest`).
- The digest guard: a non-32-byte digest is rejected with `invalidArgument`
  before any key access (`DigestGuardTest`).
- The auth-gated serialization: a second concurrent gated sign is rejected while
  the first holds the gate (`AuthSignGateTest`) - the mechanism behind
  `authInProgress`.
- The uncompressed X9.63 point encoding (`PublicKeyEncodingTest`).

The store's `generateKey` / `sign` / `getSecurityTier` / `getAttestation` and the
auth-gated `sign` compile against the real Keystore and `BiometricPrompt` APIs;
their runtime behavior against a live Keystore is exercised on the device lane
below, not in ci-android.

## Written, runs on a device or emulator lane

`AndroidKeyStoreSignerInstrumentedTest` drives the silent mechanisms end-to-end
against a live Keystore. It is not run by ci-android (unit-only, on a runner with
no emulator); it runs with `./gradlew connectedDebugAndroidTest` against a
connected device or a booted emulator:

- `generateKey` in hardware and a `getSecurityTier` re-read of the achieved tier.
- The public key is a valid 65-byte uncompressed point; the private key has no
  encoded form (`getEncoded() == null`) - the non-export proof on a real key.
- A silent signature verifies against the public key, and the raw encoding is
  64 bytes.
- An attestation challenge produces an `androidKeyChain` certificate chain; no
  challenge yields `none`.
- The existing-alias failure and idempotent `delete`.

An emulator that backs keys in the TEE proves the mechanism but not a
discrete-secure tier; a software-only emulator has no secure hardware, so key
generation there correctly fails closed rather than yielding a tier.

## Requires physical secure hardware or a UI lane

- StrongBox tier: only a device with a StrongBox security chip returns
  `SecurityLevel.strongBox` and exercises the StrongBox-to-TEE fall-back that
  fails `unavailableTier`. An emulator has none.
- The attestation chain's root of trust: the emitted chain is verified off-device
  against a hardware-attestation root, which this library never does; the chain
  is rooted in real hardware only on a physical device.
- The biometric-gated `sign` end-to-end: presenting `BiometricPrompt`,
  authenticating, and signing with the authenticated `CryptoObject` needs an
  enrolled credential and UI interaction. The serialization that yields
  `authInProgress` is proven in `AuthSignGateTest`; the full prompt-to-signature
  flow and the `userCanceled` / `authFailed` / `authContextRequired` mapping are
  checked on this lane.
- `keyInvalidated` versus biometry-any survival, for a per-use biometric-only key
  (`AUTH_BIOMETRIC_STRONG`, no validity window): `invalidateOnBiometricEnrollment =
  true` (the default) makes a real biometric re-enrollment raise
  `KeyPermanentlyInvalidatedException` on the next use; `false` lets the key survive
  and still sign. The flag is set explicitly at generation via
  `setInvalidatedByBiometricEnrollment`. Two platform caveats: a
  `biometricOrDeviceCredential` key already survives re-enrollment through its
  device-credential authenticator, independent of the flag; and the flag has no
  defined effect once `authValiditySeconds > 0`. The trigger is device-only.

## Running

- Unit logic: `cd android && ./gradlew testDebugUnitTest` (this is ci-android).
- Instrumented battery: `cd android && ./gradlew connectedDebugAndroidTest` with
  a device or emulator attached.
- Biometric flow and StrongBox tier: a device with a fingerprint or credential
  enrolled, and a StrongBox-capable device for the discrete-secure tier.
