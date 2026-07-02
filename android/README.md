# android/ (signet-android-core)

The Android native core: a Kotlin/Gradle library over `AndroidKeyStore`, providing hardware-backed P-256 keys with the StrongBox to TEE ladder, `BiometricPrompt` auth-gated signing, and X.509 key attestation. This is the single source of truth for Android; the `react-native/`, `flutter/`, and `kmp/` bindings reference it.

The design requests StrongBox, catches `StrongBoxUnavailableException`, falls back to TEE, and reports the tier read back from `KeyInfo.getSecurityLevel()`, never the requested one.

## Status

Scaffold: the module builds with a placeholder surface and no key code yet. The behavior above is the design that the key code implements and proves in tests.

## Build

The Gradle wrapper pins the toolchain, so no local Gradle install is required.

```
./gradlew assemble
./gradlew test
```
