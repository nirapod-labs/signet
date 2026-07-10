# Kotlin Multiplatform

The KMP module exposes one `expect class Signet` over the native Secure Enclave and
Android Keystore cores, the same surface on every target. Construction is
platform-specific: an Android caller builds `Signet(context)`, an Apple caller
`Signet()`, and common code receives a constructed instance. A core failure is a
`SignetException` over the closed `SignetErrorCode` set.

Signet is pre-1.0 and not yet published to Maven Central. The dependency below is
the shape for the 1.0.0 release; until then, depend on the module from a checkout.

## Install

```kotlin
// build.gradle.kts
dependencies {
    implementation("org.nirapod:signet:1.0.0")
}
```

Targets: `iosArm64`, `iosSimulatorArm64`, `macosArm64`, and Android (minSdk 24).
See [platform support](platform-support.md).

## Generate, sign, verify

```kotlin
import org.nirapod.signet.kmp.*

// `signet` is a constructed instance: Signet(context) on Android, Signet() on Apple.
val result = signet.generateKey(KeySpec(alias = "account-signing"))
println(result.report.achieved) // secureEnclave, strongBox, or tee

// `digest` is a 32-byte hash you computed; Signet signs the digest, not the message.
val signature = signet.sign(result.handle, digest) // ByteArray, DER by default

val pub = signet.getPublicKey(result.handle) // rawX962 by default
```

`result.report.achieved` is the tier the hardware delivered, never above it; a
device with no secure hardware fails closed with `SignetErrorCode.unavailableTier`
and keeps no key.

## Require a hardware floor

```kotlin
val result = signet.generateKey(
    KeySpec(
        alias = "high-value",
        tierPolicy = TierPolicy.AtLeast(HardwareClass.discreteSecure),
    ),
)
```

`TierPolicy.Strongest` (the default) takes the best tier available; `AtLeast(floor)`
fails closed below the class. A TEE-only Android device meets `trustedEnvironment`
but not `discreteSecure`.

## Gate signing behind biometrics

```kotlin
val result = signet.generateKey(
    KeySpec(
        alias = "gated",
        accessControl = AccessControlPolicy(AuthRequirement.biometricOnly),
    ),
)

// The gated overload is suspend and drives the platform biometric prompt.
// `authContext` carries the host-UI context and prompt, built on the calling
// platform (an Activity on Android, the presentation context on Apple).
val signature = signet.sign(result.handle, digest, authContext)
```

Auth-gated signing is serialized: a second call while a prompt is still outstanding
fails `SignetErrorCode.authInProgress`; a dismissed prompt is `userCanceled`.

## Read the tier, attest, delete

```kotlin
val tier = signet.getSecurityTier(result.handle)
val attestation = signet.getAttestation(result.handle) // produced, never verified
val present = signet.exists("account-signing")
signet.delete("account-signing") // idempotent
```

`getAttestation` returns a certificate chain on Android (`androidKeyChain`) and
`none` on Apple, whose Secure Enclave has no per-key attestation.

## Errors

Every call throws a `SignetException` carrying one `SignetErrorCode`. Match on the
code:

```kotlin
try {
    signet.generateKey(
        KeySpec(alias = "k", tierPolicy = TierPolicy.AtLeast(HardwareClass.discreteSecure)),
    )
} catch (e: SignetException) {
    if (e.code == SignetErrorCode.unavailableTier) {
        // No StrongBox on this device.
    }
}
```
