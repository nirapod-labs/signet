# Platform support

Signet runs on Apple and Android hardware through three bindings that share one
contract. Each binding uses the native core for its platform, and a core names
only the hardware it can reach, so no binding advertises a backing it cannot
provide.

Signet is pre-1.0 and not yet published to any registry. The package coordinates
below are reserved for the 1.0.0 release.

## Bindings

| Binding | Package | Bridge |
| --- | --- | --- |
| Flutter | `signet` (pub.dev) | Pigeon |
| React Native | `react-native-signet` (npm) | Nitro |
| Kotlin Multiplatform | `org.nirapod:signet` (Maven Central) | direct |

All three depend on the same two cores: the Swift `SignetCore` on Apple and the
`org.nirapod:signet-core` AAR on Android.

## Minimum versions

| Platform | Minimum | Secure hardware |
| --- | --- | --- |
| iOS | 15.0 | Secure Enclave |
| macOS | 12.0 | Secure Enclave |
| Android | API 24 | StrongBox or TEE-backed Keystore |

Toolchains: Swift 6.0, Android `compileSdk` 36, Dart 3.12 with Flutter 3.3,
React Native on the New Architecture, and Kotlin Multiplatform targeting
`iosArm64`, `iosSimulatorArm64`, `macosArm64`, and Android.

## Security tiers

The achieved tier is read back from the created key and reported as-is. It is
never assumed from the request and never reported stronger than the hardware
delivered.

| Tier | Hardware class | Platform | Backing |
| --- | --- | --- | --- |
| `secureEnclave` | `discreteSecure` | Apple | Secure Enclave |
| `strongBox` | `discreteSecure` | Android | StrongBox secure element |
| `tee` | `trustedEnvironment` | Android | Trusted Execution Environment |

There is no software tier. A key that cannot be placed in secure hardware is
deleted and the call fails closed with `unavailableTier`; Signet never returns a
software-backed key. Apple always reports `secureEnclave`. Android reports the
tier `KeyInfo` reads back and prefers StrongBox where the device offers it.

`discreteSecure` outranks `trustedEnvironment`. A policy of
`atLeast(discreteSecure)` requires StrongBox on Android and is met by the Secure
Enclave on Apple; a device that reaches only the TEE fails that floor closed.
