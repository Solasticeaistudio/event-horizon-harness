# Executor Attestation Verification

## Development commands

From the attestation workspace after a build:

```bash
eh-attest prove
eh-attest verify
eh-attest inspect
```

`prove` emits a simulator bundle and an encoded representation. `verify` performs a complete local issue/prove/verify cycle. `inspect` parses fields without assigning trust. Each command labels simulator output as non-hardware-backed.

## Environment variables

- `EH_ATTESTATION_API_KEY` configures the future remote verification service.
- `EH_ATTESTATION_SERVICE_URL` selects that service endpoint.
- `EH_ATTESTATION_ALLOW_SIMULATOR=1` explicitly enables development simulation outside tests.
- `EH_ATTESTATION_FORCE_HARDWARE=1` disables simulator selection where automatic selection is used.

Hardware-development variables use the same `EH_ATTESTATION_` prefix and are documented in [ATTESTATION_TPM.md](ATTESTATION_TPM.md).

## Verification contract

A successful result reports the method, trust and assurance levels, registered key identifier, independently verified measurements, canonical bundle digest, and verification time. Consumers must bind both the bundle digest and the complete verification-result digest into the same session and capability. They must not reinterpret a bundle field as a stronger trust level.

The fixed verifier tests cover method substitution, trust substitution, invalid TPM evidence, missing verifiers, nonce state, replay, and development-versus-hardware policy.
