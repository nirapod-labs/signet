# Signet

Hardware-backed P-256 signing keys for Flutter, React Native, and Kotlin Multiplatform, over Apple Secure Enclave and Android Keystore (StrongBox/TEE), with attestation and a normalized security-tier report.

> Status: pre-1.0, in active development. Not yet published to any registry.

Signet is a signing-key mechanism, not a wallet and not a policy engine. It creates a non-exportable P-256 key in the strongest hardware a device offers, signs a 32-byte digest with it, and reports honestly how strong that hardware actually is: the same API and the same tier report across every platform. The consuming application owns all policy; Signet reports and signs, it does not decide.

## What it does

- Generate a non-exportable, hardware-backed P-256 key.
- Sign a 32-byte digest (ECDSA; DER or raw r‖s), gated by biometric / device auth.
- Report the achieved security tier (`secureEnclave | strongBox | tee | tpm | software`) with the `evidence` behind it, never a claim stronger than the hardware delivered.
- Produce key attestation for a remote verifier. It produces attestation; it does not verify it.

Private keys never leave hardware; no export path exists in any surface. The library holds no keys and runs no server.

## Platforms

Signet targets iOS, macOS, and Android across three bindings: Flutter (Pigeon), React Native (Nitro), and Kotlin Multiplatform.

The native cores live at `apple/` (Swift, Secure Enclave) and `android/` (Kotlin, Keystore); the bindings at `react-native/`, `flutter/`, and `kmp/` reference them. The cross-language contract is data in `conformance/`.

## Build

```
make bootstrap   # brew deps, pnpm install, git hooks
make help        # the task surface
```

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3.
