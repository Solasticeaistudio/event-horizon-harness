# Renaming Notes

The internal prototype name was replaced with the descriptive public name **Executor Attestation**. It is one subsystem of Event Horizon, not a separate product.

| Previous internal name | Current name |
|---|---|
| HardProof / Hardproof | Executor Attestation |
| `hardproof/` | `attestation/` |
| `@hardproof/sdk` | `@event-horizon/attestation-sdk` |
| `@hardproof/core` | `@event-horizon/attestation-core` |
| `@hardproof/crypto` | `@event-horizon/attestation-crypto` |
| `@hardproof/simulator` | `@event-horizon/attestation-simulator` |
| `@hardproof/prover-tpm` | `@event-horizon/attestation-tpm` |
| `@hardproof/middleware` | `@event-horizon/attestation-middleware` |
| `HardproofError` | `AttestationError` |
| `HardproofBundle` | `AttestationBundle` |
| `HardproofErrorCode` | `AttestationErrorCode` |
| `HardProofDevelopmentProvider` | `DevelopmentAttestationProvider` |
| `HardProofProvider` | `AttestationProvider` |
| `hardproofMiddleware` | `attestationMiddleware` |
| `hardproof` CLI | `eh-attest` |
| `HARDPROOF_*` environment variables | `EH_ATTESTATION_*` environment variables |
