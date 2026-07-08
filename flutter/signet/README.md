# signet

The Flutter binding for Signet: hardware-backed P-256 signing keys that stay in
dedicated secure hardware.

Every private key is generated in, and confined to, the platform's secure
hardware: the Apple Secure Enclave on iOS and macOS, or a StrongBox or TEE-backed
key in the Android Keystore. There is no software-key path and no software
fallback. When the required secure hardware is not reachable, key generation fails
closed with `SignetErrorCode.unavailableTier`; it never degrades to a software
key.

The binding itself holds no key material and no policy. It is a thin Pigeon
channel that marshals each call to the native core (`../apple`, `../android`),
which is the only code that touches the hardware. The public Dart API is in
`lib/signet.dart`.

## Usage

```dart
import 'dart:typed_data';
import 'package:signet/signet.dart';

final signet = Signet();

// Generate a non-exportable key in the strongest available hardware.
final (handle, report) = await signet.generateKey(alias: 'wallet');

// Read the public key and sign a 32-byte digest.
final publicKey = await signet.getPublicKey(handle);
final signature = await signet.sign(handle, digest); // digest.length == 32
```

A key can require a presence check (biometric, or biometric or device credential)
through `AuthRequirement`. A gated key is signed by passing an `AuthPrompt`, which
the native side presents and authenticates against the hardware key directly.

## Verification

See `flutter/VERIFICATION.md` for what each layer proves: the Dart contract under
CI, a local three-platform compile, and the device-lane integration tests.
