# React Native

The React Native binding is a Nitro module over the native Secure Enclave and
Android Keystore cores. It requires the New Architecture. Most calls are
synchronous over JSI; only `sign` is async. A core failure arrives as a
`SignetError` over the closed error set.

Signet is pre-1.0 and not yet published to npm. The install below is the shape for
the 1.0.0 release; until then, depend on the package from a checkout.

## Install

```sh
npm install react-native-signet react-native-nitro-modules
cd ios && pod install
```

Minimum: iOS 15, macOS 12, Android API 24, React Native on the New Architecture.
See [platform support](platform-support.md).

## Generate, sign, verify

```ts
import { Signet, atLeast } from 'react-native-signet'

// A silent, non-exportable key in the strongest hardware available.
const { handle, report } = Signet.generateKey({ alias: 'account-signing' })
console.log(report.achieved) // 'secureEnclave' | 'strongBox' | 'tee'

// `digest` is a 32-byte ArrayBuffer you computed; Signet signs the digest.
const signature = await Signet.sign(handle, digest) // ArrayBuffer, DER by default

const pub = Signet.getPublicKey(handle) // rawX962 by default
```

`report.achieved` is the tier the hardware delivered, never inflated; a device with
no secure hardware fails closed with the `unavailableTier` code and keeps no key.
`generateKey` and `getPublicKey` are synchronous; `sign` returns a `Promise`.

## Require a hardware floor

```ts
const { report } = Signet.generateKey({
  alias: 'high-value',
  tierPolicy: atLeast('discreteSecure'),
})
```

`strongest` (the default) takes the best tier available; `atLeast(floor)` fails
closed below the class. A TEE-only Android device meets `trustedEnvironment` but
not `discreteSecure`.

## Gate signing behind biometrics

```ts
const { handle } = Signet.generateKey({
  alias: 'gated',
  accessControl: { authRequirement: 'biometricOnly' },
})

const signature = await Signet.sign(handle, digest, undefined, {
  title: 'Authorize',
  authRequirement: 'biometricOnly',
})
```

The native side presents the prompt and signs with the hardware key directly; the
private key never crosses the bridge. A dismissed prompt is the `userCanceled`
code; a second concurrent gated sign is `authInProgress`.

## Read the tier, attest, delete

```ts
const tier = Signet.getSecurityTier(handle)
const attestation = Signet.getAttestation(handle) // produced, never verified
const present = Signet.exists('account-signing')
Signet.delete('account-signing') // idempotent
```

`getAttestation` returns a certificate chain on Android (`androidKeyChain`) and
`none` on Apple, whose Secure Enclave has no per-key attestation.

## Errors

Every call throws a `SignetError` carrying one `code` from the closed set. Match on
`code`, never the message:

```ts
import { SignetError } from 'react-native-signet'

try {
  Signet.generateKey({ alias: 'k', tierPolicy: atLeast('discreteSecure') })
} catch (e) {
  if (e instanceof SignetError && e.code === 'unavailableTier') {
    // No StrongBox on this device.
  }
}
```
