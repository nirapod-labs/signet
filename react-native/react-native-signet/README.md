# react-native-signet

Hardware-backed P-256 signing for React Native on iOS, macOS, and Android. Every
private key stays in dedicated secure hardware: the Apple Secure Enclave on iOS and
macOS, and Android StrongBox or the TEE-backed Keystore on Android. There is no
software-key path. When the required hardware is not reachable, the call fails
closed and throws `unavailableTier` rather than dropping to a software key.

The binding is a thin [Nitro](https://nitro.margelo.com) HybridObject over the
`apple/` and `android/` native cores. It carries no key material and no
cryptography of its own; the private key never crosses into JavaScript and has no
export path.

## Requirements

- React Native 0.81 or newer, with the New Architecture enabled
- `react-native-nitro-modules` as a peer dependency

## Installation

```bash
npm install react-native-signet react-native-nitro-modules
```

## Usage

```ts
import { Signet, strongest } from 'react-native-signet'

// Generate a non-exportable key in the strongest available secure hardware.
const { handle, report } = Signet.generateKey({
  alias: 'demo-key',
  tierPolicy: strongest,
})
console.log(report.achieved) // 'secureEnclave' | 'strongBox' | 'tee'

// Sign a 32-byte digest (for example a SHA-256 hash) with a silent key.
const signature = await Signet.sign(handle, digest, { encoding: 'der' })
```

To require the user to be present at sign time, bind an `accessControl` at
generation and pass an `AuthPrompt` to `sign`. The native side presents the
biometric prompt and authenticates the hardware key directly; the digest is signed
only after a successful check.

Select a hardware floor with `atLeast(...)` when a key must reach at least a given
hardware class, or `strongest` for the best tier the device offers. A policy whose
floor is not met fails closed and keeps no key.

## Platform notes

The Secure Enclave is not present on the iOS simulator, so signing needs a real
iOS device or a Mac with a Secure Enclave. On Android, StrongBox requires
supporting hardware; a device without it reports the `tee` tier from the
TEE-backed Keystore, and a build with no secure Keystore fails closed instead of
returning a software key.

`VERIFICATION.md` records what CI checks and what needs a device.

## Contributing

Pull requests are welcome. Please open an issue first for any change to the public
API or the wire contract in `src/specs/signet.nitro.ts`.

## License

Apache-2.0. See [`LICENSE`](https://github.com/nirapod-labs/signet/blob/main/LICENSE).
