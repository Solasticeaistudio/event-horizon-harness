# Executor Attestation TPM 2.0 path

## Verified path

The Linux provider explicitly provisions or loads an RSA Attestation Key at configured persistent EK/AK handles (defaults `0x81010001` and `0x81010002`), obtains a verifier-issued one-time nonce, invokes `tpm2_quote` for the configured PCRs, and returns the binary `TPMS_ATTEST`, quote signature, PCR values, AK qualified name, optional normalized event log, and a separate attestation-key signature over the complete canonical bundle. Provisioning refuses to overwrite occupied handles and saves a verified serialized AK handle rather than trusting a raw number. The provider-specific verifier:

1. Parses the bounded binary quote and requires TPM generated magic and quote attestation type.
2. Matches the AK qualified signer and pre-registered AK public key/key ID.
3. Matches the quote extra data to the issued nonce and consumes that nonce once.
4. Verifies the RSASSA-SHA256 quote signature.
5. Requires the exact configured PCR selection and reconstructs the signed composite digest.
6. Replays normalized event digests into PCRs when an event log is supplied or required.
7. Verifies the attestation key's separate signature over every bundle field, including method, device, nonce, timestamps, measurements, and quote evidence.
8. Applies freshness and expiry checks before returning hardware trust; the outer verifier then enforces replay state.

Executor Attestation returns identity and measurement evidence only. Event Horizon policy and capability processes make the authorization decision.

## Deterministic fixtures

```bash
npm ci
npm run build
npm test
```

The fixture suite covers valid, tampered PCR, stale, replayed, wrong-AK, wrong-PCR, tampered/missing event-log, whole-bundle integrity, unknown/expired nonce, missing-provider, method-substitution, and trust-substitution cases. These synthetic signed quotes test parser/verifier behavior but are not hardware evidence.

## `swtpm` command-path integration

On Linux with `swtpm`, `tpm2-tools`, Node, and npm installed:

```bash
./scripts/run-swtpm-attestation.sh
```

The helper starts a temporary TPM 2.0 simulator, provisions a new AK without overwriting any existing material, enables the normally skipped integration test, and removes only its own `mktemp` directory. This exercises the real Linux tooling path but must not be labeled hardware-rooted operational evidence.

The helper is an opt-in integration target and is not part of the portable CI claim. It must pass the same provider-specific verification path, including `tpm2_sign` whole-bundle integrity, before its result is accepted.

## Real Linux TPM

Provision into a dedicated directory exactly once:

```bash
EH_ATTESTATION_REAL_TPM=1 \
EH_ATTESTATION_TPM_WORKDIR=/var/lib/attestation/ak \
EH_ATTESTATION_TPM_PROVISION_AK=1 \
npm test
```

For later runs omit `EH_ATTESTATION_TPM_PROVISION_AK`; the existing context, PEM public key, and qualified-name files are loaded. A non-device TCTI may be set with `EH_ATTESTATION_TPM_TCTI`. A normalized event-log JSON file may be set with `EH_ATTESTATION_TPM_EVENT_LOG_JSON`; entries have exactly `bank`, `pcr`, and hex `digest` fields.

Missing devices, tools, AK files, invalid quotes, unavailable hardware, or a failure to sign the complete bundle deny verification. There is no production simulator fallback. Cross-vendor TPM enrollment and quote conformance remain incomplete and are not claimed by this artifact.
