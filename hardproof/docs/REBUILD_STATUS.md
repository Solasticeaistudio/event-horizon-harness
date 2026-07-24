# Rebuild status

The original repository was unavailable. This implementation was reconstructed from the recovered SDK design document and the Assurance/Proof concepts already present in Solstice.

## Implemented

- `@hardproof/crypto`: canonicalization, SHA-256, base64url, deterministic Ed25519 keys, detached signatures, key IDs.
- `@hardproof/core`: bundle model, nonce store, device registry, PCR policy, freshness checks, signature verification, replay protection.
- `@hardproof/simulator`: deterministic local prover suitable for development and CI.
- `@hardproof/prover-tpm`: platform detection and a strict provider interface. It never silently falls back to software in production.
- `@hardproof/sdk`: `Client`, `Server`, bundle helpers, typed events, typed errors, local verification.
- `@hardproof/middleware`: Express-compatible verification middleware without an Express dependency.
- `@hardproof/cli`: local end-to-end demonstration.
- `@hardproof/cloud`: minimal in-memory nonce and verification service starter.

## Deliberately incomplete

The TPM adapter does not yet claim production quote verification. Platform TPM tooling differs across Linux and Windows, AK provisioning must be explicit, and raw quote parsing must be independently tested. The default adapter therefore fails closed with `PROVER_NOT_IMPLEMENTED` unless a concrete `TpmQuoteProvider` is supplied.

## Security corrections from the old design

- No HMAC proof format for production-facing bundles.
- Verifiers do not trust arbitrary self-declared public keys, except explicitly enabled simulator development mode.
- Nonces are consumed once.
- Complete proof digests are replay-tracked.
- Unknown bundle versions and methods are rejected.
- Simulator use outside test/development requires explicit opt-in.
- HardProof emits identity/measurement evidence only; authorization remains external.
