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

The simulator is not hardware attestation. The local verifier and evidence recorder are not physically isolated services. The shipped SQLite nonce backend covers cooperating processes on one host and one local database, not multiple hosts or hostile database clients. A production TPM enrollment and endorsement hierarchy is not yet delivered.

The shipped nonce backend records device, executor, session, purpose, issuance time, expiration time, state, and canonical context digest. It performs `issued -> consumed` as one conditional SQLite update shared by local verifier processes. The database file and WAL must remain outside the hostile executor and protected against deletion, replacement, or rollback. A future multi-host backend must preserve the compare-and-transition as one linearizable server-side transaction; a check followed by a separate delete is not sufficient.
