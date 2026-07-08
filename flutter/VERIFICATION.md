# Signet Flutter binding verification

The Flutter binding is a thin Pigeon channel over the `apple/` and `android/`
cores. It holds no key material and no cryptography; every security-bearing
operation runs in a core. This records which of its claims are checked by CI
here, which are checked by a local build, and which need a real device.

## Checked by CI (ci-flutter-lib)

`flutter analyze` and `flutter test` on `flutter/signet` run on every change to
the binding or a core it consumes. They cover the pure Dart layer with no native
side, through a `SignetHostApi` fake injected into `Signet`:

- Every request marshals to the wire structs: the tier policy, the access-control
  request (auth requirement, validity window, enrollment invalidation), the
  attestation challenge, and the sign options.
- A silent sign passes a null prompt; a gated sign marshals the `AuthPrompt`.
- Every closed-set error token maps to its `SignetErrorCode`, an unknown code
  maps to `hardwareError`, and the platform message is carried through.

These prove the Dart contract and its mapping, not the hardware behind it.

## Checked by a local build (all three platforms compile)

The native plugin and the cores it links compile on each platform, which the
Dart-only CI does not exercise:

- Android: `flutter build apk` compiles the plugin and the `android/` core in
  the same module.
- iOS and macOS: `flutter build ios --no-codesign` and `flutter build macos`
  compile the shared `darwin/` plugin and link the `apple/` core as the
  `SignetCore` pod.

The cores are linked dev-local: the example Podfiles reference `../../../apple`
by path and pin the iOS 15 / macOS 12 deployment targets the plugin needs. A
published plugin carries the core as a versioned pod instead; the "does not
support Swift Package Manager" build warning is the same publish-later item. The
example's generated Xcode projects are gitignored and regenerated locally.

## Requires a real device (integration_test)

`flutter/SignetApp/integration_test` runs against the real key store on a
connected device or emulator; it is not run by CI. It covers:

- The non-interactive surface end to end: generate (best effort), read the
  public key, sign a digest, delete.
- Gated-key generation reporting its auth class. Generating a gated key does not
  prompt; it needs an enrolled biometric on the device.

## Requires a physical device and a person (interactive)

The auth-gated sign presents a biometric prompt the native side owns; it cannot
be scripted. On a physical device, by hand through the example's "Generate gated
key and sign" action:

- A gated sign presents the prompt and, on success, returns a signature the
  public key verifies. It is serialized: a second concurrent gated sign is
  rejected `authInProgress`.
- The prompt outcomes map to the closed set: a dismissed prompt is
  `userCanceled`, a failed authentication is `authFailed`, and a gated key with
  no host UI (a plain activity, not `FlutterFragmentActivity`) is
  `authContextRequired`.
- Apple has no dedicated code for a key invalidated by biometric re-enrollment,
  so on iOS and macOS that surfaces as `authFailed`, not `keyInvalidated`
  (Android raises `keyInvalidated`). The Apple gated-sign error mapping is
  written against the current SDK headers and confirmed on a device; this Mac's
  Enclave is code-signing-blocked and cannot run it.
- StrongBox tier and a real Android attestation chain, inherited from the
  `android/` core's own device lane.

## Inherited from the cores

The binding adds no cryptography. Signature encoding, the DER-to-raw conversion,
tier selection, and the closed error set are the cores', already exercised by
the `apple/` and `android/` unit tests and their verification ledgers. The Dart
conformance runner is a no-silent-skip stub: it imports Flutter and cannot run as
a standalone process, so the binding's device-lane conformance is the
integration_test above.

## Running

- CI layer: `cd flutter/signet && flutter analyze && flutter test`.
- Local compile: from `flutter/SignetApp`, `flutter build apk`,
  `flutter build ios --no-codesign`, `flutter build macos`.
- Device lane: `cd flutter/SignetApp && flutter test integration_test` with a
  device attached; the interactive gated sign is exercised by hand.
