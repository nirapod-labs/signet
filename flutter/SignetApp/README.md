# SignetApp

The example app for the `signet` plugin. It drives the plugin against the real
platform key store: generating a non-exportable P-256 key in secure hardware,
reading its public key, signing a digest, running an auth-gated sign, and showing
the security tier report the native core reads back from the created key.

## Running

```sh
flutter run
```

Run it on a physical device to reach the Secure Enclave (iOS and macOS) or a
StrongBox or TEE-backed Keystore (Android). On a device or emulator with no secure
hardware, key generation fails closed rather than falling back to a software key.

The device-lane integration tests are in `integration_test/`; see
`flutter/VERIFICATION.md` for what each layer proves.
