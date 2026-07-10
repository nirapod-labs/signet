# Contributing to Signet

## Ground rules

- **Design before code.** A change to the API, a type, an error, or the tier model changes the contract in `conformance/` and must land with matching updates in every binding.
- **PR-driven.** No direct pushes to `main` (the pre-push hook enforces this locally). Branch, open a PR, let CI run.
- **Conventional commits.** Enforced by commitlint. Types: `feat, fix, docs, refactor, test, build, ci, chore`. Scopes are in `.commitlintrc.json`. Subject ≤ 50 characters.
- **Small, coherent PRs.** One safe-to-merge unit per PR.

## Setup

```
make bootstrap
```

Installs the brew toolchain (`Brewfile`), the pnpm dev deps, and the lefthook git hooks.

## Running the examples

The example apps in `flutter/SignetApp`, `react-native/SignetApp`, and `kmp/SignetApp` use automatic Xcode signing and carry no team ID. To run one on an Apple device or a signed simulator build, open it in Xcode and set your own team under Signing & Capabilities; Android needs no signing setup. Secure Enclave and StrongBox exist only on real hardware, so key creation fails closed on a simulator or an emulator without a secure keystore; run the examples on a device to exercise the full flow.

## Before you push

- `make lint` (Biome) is clean.
- The relevant native/binding tests pass.
- If you touched the contract (`conformance/`), the conformance suite is green across all four bindings.

## Security-sensitive changes

Anything touching key creation, signing, access control, attestation, or the tier report is on the critical path. Keep the non-custodial invariants intact: keys never leave hardware, no export path, no key material across a binding boundary, no silent tier downgrade. See `SECURITY.md`.
