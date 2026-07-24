# Rebuild status

The original repository was unavailable. This clean-room implementation was reconstructed from the recovered SDK design and Event Horizon assurance concepts.

## Implemented

- `@event-horizon/attestation-crypto`: canonicalization, SHA-256, base64url, Ed25519 helpers, detached signatures, key IDs.
- `@event-horizon/attestation-core`: bundle/nonce/device registries, deterministic simulator verification, bounded `TPMS_ATTEST` parsing, AK registration, RSA quote signature verification, exact PCR reconstruction, optional normalized event-log validation, freshness and replay enforcement.
- `@event-horizon/attestation-simulator`: deterministic development/CI prover.
- `@event-horizon/attestation-tpm`: explicit Linux `tpm2-tools` AK creation/loading and nonce-bound quote acquisition; no silent fallback.
- `@event-horizon/attestation-sdk`, middleware, CLI, and development cloud packages.
- Synthetic TPM fixtures for valid and negative cases plus an opt-in real Linux TPM/`swtpm` integration test.

## Claim boundary

The Linux path is implemented and fail-closed, but it is production evidence only when run against an authentic registered hardware AK with a reviewed PCR and event-log policy. The `swtpm` runner and deterministic fixtures validate behavior, not hardware provenance. Windows TPM, macOS Secure Enclave, and Android Keystore providers remain outside this implementation.

Executor Attestation remains authorization-free: it proves registered identity and configured measurements, while Event Horizon separately decides whether an exact action may occur.

## Security properties

- Verifier-issued nonces are one-time and expire.
- Complete proofs are replay tracked.
- AK public key, key ID, qualified signer, quote nonce, PCR selection, PCR values/composite, signature, timestamps, and event log are independently checked.
- Unknown fields, algorithms, bundle methods/versions, devices, and unavailable TPM providers fail closed.
- Simulator use remains explicit and cannot silently replace the production TPM provider.
