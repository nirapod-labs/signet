# Signet for Kotlin Multiplatform

`signet` is the Kotlin Multiplatform binding for Signet. It exposes hardware-backed
P-256 signing keys to KMP consumers on Android (Keystore, StrongBox or TEE), Apple
platforms (Secure Enclave), and the desktop JVM.

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

`androidLibrary`, `jvm` (desktop), `iosArm64`, `iosSimulatorArm64`.
Coordinates `xyz.nirapod:signet`.
