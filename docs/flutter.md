# Flutter

The Flutter binding is a Pigeon channel over the native Secure Enclave and Android
Keystore cores. The API is async: every call marshals to the core and rebuilds a
typed result, and a core failure arrives as a `SignetException` over the closed
`SignetErrorCode` set. No policy and no key material live in Dart.

Signet is pre-1.0 and not yet published to pub.dev. The dependency below is the
shape for the 1.0.0 release; until then, depend on the package from a checkout.

## Install

```yaml
# pubspec.yaml
dependencies:
  signet: ^1.0.0
```

Minimum: iOS 15, macOS 12, Android API 24. See [platform support](platform-support.md).

## Generate, sign, verify

```dart
import 'package:signet/signet.dart';

final signet = Signet();

// A silent, non-exportable key in the strongest hardware the device offers.
final (handle, report) = await signet.generateKey(alias: 'account-signing');
print(report.achieved); // secureEnclave, strongBox, or tee

// `digest` is a 32-byte hash you computed; Signet signs the digest, not the message.
final signature = await signet.sign(handle, digest); // Uint8List, DER by default

// The public key, for a verifier off-device.
final pub = await signet.getPublicKey(handle); // rawX962 by default
```

`generateKey` returns the handle and its tier report together. `report.achieved`
is the tier the hardware delivered, never a claim above it; a device with no secure
hardware fails closed with `SignetErrorCode.unavailableTier` and keeps no key.

## Require a hardware floor

```dart
// Fail unless the key lands in a discrete secure element (StrongBox / Secure Enclave).
final (handle, report) = await signet.generateKey(
  alias: 'high-value',
  tierPolicy: const AtLeast(HardwareClass.discreteSecure),
);
```

`Strongest` (the default) takes the best tier available; `AtLeast(floor)` fails
closed below the class. A TEE-only Android device meets `trustedEnvironment` but
not `discreteSecure`.

## Gate signing behind biometrics

```dart
final (handle, _) = await signet.generateKey(
  alias: 'gated',
  authRequirement: AuthRequirement.biometricOnly,
);

final signature = await signet.sign(
  handle,
  digest,
  prompt: const AuthPrompt(
    title: 'Authorize',
    authRequirement: AuthRequirement.biometricOnly,
  ),
);
```

The native side presents the prompt and authenticates the hardware key directly;
the private key never crosses the channel. A dismissed prompt is
`SignetErrorCode.userCanceled`; a second concurrent gated sign is `authInProgress`.

## Read the tier, attest, delete

```dart
final tier = await signet.getSecurityTier(handle);
final attestation = await signet.getAttestation(handle); // produced, never verified
final present = await signet.exists('account-signing');
await signet.delete('account-signing'); // idempotent
```

`getAttestation` returns a certificate chain on Android (`androidKeyChain`) and
`none` on Apple, whose Secure Enclave has no per-key attestation. Signet produces
the attestation; verifying it is a remote verifier's job.

## Errors

Every call throws a `SignetException` carrying one `SignetErrorCode`. Match on
`code`, never the message:

```dart
try {
  await signet.generateKey(
    alias: 'k',
    tierPolicy: const AtLeast(HardwareClass.discreteSecure),
  );
} on SignetException catch (e) {
  if (e.code == SignetErrorCode.unavailableTier) {
    // No StrongBox on this device.
  }
}
```
