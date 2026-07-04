# Signet App (Kotlin Multiplatform)

Consumer example for the `signet` Kotlin Multiplatform library. It composite-builds
the sibling `../signet` library and exercises its public surface from `commonMain`,
proving the contract is consumable from a separate Kotlin Multiplatform project.

`src/commonMain/kotlin/xyz/nirapod/signet/example/Demo.kt` holds the shared flow: a
host constructs the platform `Signet` (`Signet(context)` on Android, `Signet()` on
Apple) and passes it to `SignetDemo.run`, which generates a key, reads its public key
and tier, signs a digest, reads the attestation, and deletes the key. It holds no key
material and has no export path.

## Build

```
cd SignetApp
./gradlew compileKotlinMacosArm64
```

The Apple targets (`iosArm64`, `iosSimulatorArm64`, `macosArm64`) compile against the
composite-built library. An on-device host UI and an Android application target are
future work.
