# android/ (signet-core)

The Android native core: a Kotlin/Gradle library over `AndroidKeyStore`, providing hardware-backed P-256 keys with the StrongBox to TEE ladder, `BiometricPrompt` auth-gated signing, and X.509 key attestation. This is the single source of truth for Android; the `react-native/`, `flutter/`, and `kmp/` bindings reference it.

The design requests StrongBox, catches `StrongBoxUnavailableException`, falls back to TEE, and reports the tier read back from `KeyInfo.getSecurityLevel()`, never the requested one.

## Status

The Keystore core ships. `AndroidKeyStoreSigner` implements key generation, silent and auth-gated signing, tier read-back, and X.509 key attestation against `AndroidKeyStore`. There is no software-key path: a key that cannot be created in secure hardware is deleted and the call fails closed (`unavailableTier`). JVM unit tests cover the pure logic; the live-Keystore behavior runs on the instrumented lane. See `VERIFICATION.md`.

## Build

The Gradle wrapper pins the toolchain, so no local Gradle install is required.

```
./gradlew assemble
./gradlew test
```
