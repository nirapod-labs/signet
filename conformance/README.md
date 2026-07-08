# Signet conformance contract

This directory is the single source of truth for Signet's cross-language contract. Every binding (Dart, TypeScript, Kotlin, Swift) and the polyglot conformance runner read these files. They are not documentation; they are the spec.

- `security-level.json`: the `SecurityLevel` enum, the `TierEvidence` enum, and the tier-class partial order that the `atLeast(HardwareClass)` floor enforces.
- `errors.json`: the one closed error set every binding raises.
- `shapes.json`: the normalized shapes (`SecurityTierReport`, `AttestationResult`, `KeySpec`, `AccessControlPolicy`, `SignOptions`, `PublicKey`) and the primitive signatures.
- `behaviors.yaml`: the cross-language behaviors asserted identically in every runner. A behavior unimplemented in any runner is a hard failure.
- `vectors.json`: golden test vectors shared across the runners.

A change here is a contract change: it must land with matching updates in all four bindings and a green conformance run.

## Harness

`harness/driver.mjs` is the polyglot driver. It loads this contract and drives four independent language runners under `runners/` (TypeScript, Dart, Kotlin, Swift) over a line-delimited JSON protocol on stdio: for each behavior it writes `{"behavior": id}` and the runner answers `{"behavior": id, "status": ...}`. A behavior passes only when every runner answers `pass`. A runner that omits an answer is a silent skip and fails the run, so an unimplemented behavior can never be mistaken for a passing one. The driver also refuses to load a contract whose shapes can name a private key, or one that reintroduces a removed tier or the retired tier-floor vocabulary.

Run it with Node (no dependencies):

```
node harness/driver.mjs
```

At this milestone every runner is a stub that answers `unimplemented`, so the suite is red until the cores and bindings land.
