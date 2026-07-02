# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's "Report a vulnerability" (Security → Advisories) on `nirapod-labs/signet`. Do not open a public issue for a security report. You will get an acknowledgement and a coordinated-disclosure timeline.

## Security model

Signet is a non-custodial signing mechanism. Its invariants:

- Private keys are generated in hardware (Secure Enclave / StrongBox / TEE / TPM) and **never leave it**. No surface exposes a private-key export path.
- No key material crosses a binding boundary: only opaque handles, digests, signatures, public keys, and attestation blobs.
- The reported security tier is the **achieved** tier, read back from the created key, with the `evidence` behind it. The library never claims a stronger tier than the hardware delivered, and never silently downgrades.
- Signet **produces** attestation; it never verifies it. Verification is a remote verifier's job, off-device.

The trust anchors are the device hardware and a remote verifier. Code running in the app process (native or binding) is not privileged relative to those anchors.

## Scope

In scope: key extraction, tier misreporting, attestation forgery that would survive off-device verification, auth-gate bypass, key-material leakage across a boundary. Out of scope: attacks that require an already-compromised device where the attacker acts while the user is present and authenticates, and trusted-display guarantees (a phone has no trusted display).
