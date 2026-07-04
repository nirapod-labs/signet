# Signet for Kotlin Multiplatform

`signet` is the Kotlin Multiplatform binding for Signet. It exposes hardware-backed
P-256 signing keys to KMP consumers on Android (Keystore, StrongBox or TEE) and Apple
platforms (Secure Enclave) on iOS and macOS.

## Layout

- `signet/` is the self-contained Gradle project for the published library.
- `SignetApp/` is the consumer example.

## Build

The Gradle wrapper pins the toolchain, so no local Gradle install is required.

```
cd signet
./gradlew assemble
./gradlew allTests
```

## Targets

`androidLibrary`, `iosArm64`, `iosSimulatorArm64`, `macosArm64`. Coordinates
`xyz.nirapod:signet`.
