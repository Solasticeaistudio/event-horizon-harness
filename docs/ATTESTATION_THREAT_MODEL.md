# Executor Attestation Threat Model

## Assumptions

The sacrificial executor, its filesystem, its process memory, its bundle construction code, and all caller-provided strings are assumed compromised. An attacker may replay, reorder, substitute, truncate, extend, or concurrently submit bundles. The verifier configuration, nonce authority, registered device keys, accepted measurement policy, and verifier process are trusted computing base components.

## Security goals

- A bundle cannot acquire trust from a self-declared method or trust-level field.
- Every accepted nonce was issued for the verified context and is consumed atomically once.
- A simulator result is always labeled development trust and cannot satisfy hardware-only policy.
- TPM hardware trust requires independent nonce, quote-signature, attestation-key, PCR-selection, PCR-value, measurement-policy, freshness, and bundle-integrity validation.
- Missing or malformed providers, verifier exceptions, unknown methods, stale bundles, and replay all fail closed.
- Attestation can veto capability issuance but cannot widen the deterministic static-policy ceiling.

## Out of scope today

The simulator is not hardware attestation. The local verifier and evidence recorder are not physically isolated services. Distributed atomic nonce consumption has an interface but no production Redis or transactional-database implementation. A production TPM enrollment and endorsement hierarchy is not yet delivered.
