# SignetAppleCore verification

The Apple core's security claims rest on the Secure Enclave. This records which
are checked by a test against a real Enclave here, and which need a signed
device (or a lane that gives the simulator a real Enclave) that unsigned CI
cannot provide.

## Checked against a real Enclave (unsigned `swift test`)

`SecureEnclaveMechanismTests` builds a transient Secure Enclave key from the
store's own access flags and asserts the invariants the store's guarantees rest
on:

- The private key has no external representation; only the public key exports,
  as a 65-byte X9.63 point. The private key never leaves the Enclave.
- A signature over a 32-byte digest verifies against the public key, and its DER
  encoding converts to the fixed 64-byte `r || s` form through the store's own
  parser.

A transient key is not written to the keychain; it needs no entitlement and
runs wherever an Enclave is reachable. On a host or runner without one, these
tests step aside.

## Requires a signed device or Enclave-simulator lane

The store's public API creates permanent, data-protection-keychain keys.
Persisting a key to that keychain needs an entitlement carried by a provisioning
profile, which an unsigned binary does not have: `SecKeyCreateRandomKey` mints
the key in the Enclave, then fails to add it with `errSecMissingEntitlement`
(-34018). `KeyLifecycleTests` probes for a reachable Enclave and steps aside
where it cannot create a key; a green unsigned run does not by itself prove
the persisted-key path. That path is verified on a signed device, or a lane that
supplies a real Enclave to the simulator:

- `generateKey` / `exists` / `delete` lifecycle, and the existing-alias failure.
- `getPublicKey`, and `sign` producing a verifiable signature through a
  persisted key.
- `getSecurityTier` and `getAttestation` on a persisted key.
- The persisted private key has no external representation.
- `exists` and `fetchKey` match only Secure Enclave items: a non-Enclave key
  placed under the same tag is not matched, while `delete` still clears it.

## Running

- Mechanism proof: `cd apple && swift test`. On a machine with a Secure Enclave
  this executes the mechanism tests; the lifecycle tests step aside.
- Full lifecycle: run the test target on a signed device, or a Secure Enclave
  simulator lane, where the data-protection keychain is available.
