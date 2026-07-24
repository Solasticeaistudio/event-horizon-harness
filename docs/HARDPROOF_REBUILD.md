# HardProof reconstruction

The original HardProof repository is considered lost. The recovered Phase 5 SDK design is preserved at `hardproof/docs/SDK_DESIGN_RECOVERED.md` and was used as the API contract for this clean-room rebuild.

## Recovered intent

HardProof is a proof-agnostic attestation layer with:

- a developer-facing `Client` for proof generation;
- a backend-facing `Server` for proof verification;
- lower-level prover packages;
- device registration;
- nonce-bound evidence;
- short-lived sessions;
- event-driven observability;
- simulator support for development;
- TPM, Secure Enclave, and Android Keystore targets.

## Rebuilt now

The local development path is functional end to end:

```text
Server.nonce.issue()
  -> Client.prove()
  -> deterministic simulator creates measured Ed25519 proof
  -> Server.verify()
  -> device identity, freshness, signature, replay and measurement policy validated
  -> Event Horizon receives signed verification evidence
```

The HardProof result is used only as a guardian input. It cannot authorize operations or mint Event Horizon capabilities.

## Remaining production work

1. Linux TPM 2.0 AK provisioning and quote generation
2. Independent TPMS_ATTEST parsing and signature verification
3. PCR bank and event-log policy validation
4. Windows TPM/TBS provider
5. Device enrollment and certificate lifecycle
6. Cloud nonce and verification routes
7. JWKS-backed attestation sessions
8. Separate verifier appliance/process
9. Key rotation and revocation
10. Conformance fixtures against multiple TPM vendors
