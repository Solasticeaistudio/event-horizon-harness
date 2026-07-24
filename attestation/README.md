# Executor Attestation rebuild

Executor Attestation is a local-first, proof-agnostic attestation SDK rebuilt from the recovered Phase 5 SDK specification.

This reconstruction separates three concerns:

1. **Provers** produce nonce-bound evidence.
2. **Core verification** validates identity, freshness, signatures, measurements, and replay state.
3. **SDK surfaces** expose the developer-facing `Client` and `Server` APIs.

## Current status

Working now:

- deterministic simulator prover;
- Ed25519 proof signatures;
- canonical proof bundles;
- nonce issuance and one-time consumption;
- proof replay detection;
- device-key registration;
- exact PCR-style measurement policies;
- local `Client.prove()` and `Server.verify()`;
- typed events and actionable `AttestationError` values;
- bundle encode/decode helpers;
- Express-compatible middleware;
- CLI demonstration;
- in-memory cloud API starter.

Scaffolded and fail-closed:

- TPM 2.0 command adapter;
- device registration ceremony;
- cloud-backed verification;
- attestation sessions and JWKS;
- Secure Enclave and Android Keystore provers.

## Run

```bash
npm install
npm run build
npm test
npm run demo
```

No third-party runtime dependencies are required for the local simulator path.

## Event Horizon boundary

Executor Attestation proves an executor identity and measurement. It does **not** decide what an agent may do. Event Horizon consumes a successful attestation as one veto input before its capability broker issues exact, one-use authority.

See `docs/REBUILD_STATUS.md`, `docs/EVENT_HORIZON_INTEGRATION.md`, and `docs/SDK_DESIGN_RECOVERED.md`.
