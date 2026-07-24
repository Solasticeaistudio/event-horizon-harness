# HardProof TPM 2.0 path

## Verified path

The Linux provider explicitly provisions or loads an RSA Attestation Key at configured persistent EK/AK handles (defaults `0x81010001` and `0x81010002`), obtains a verifier-issued one-time nonce, invokes `tpm2_quote` for the configured PCRs, and returns the binary `TPMS_ATTEST`, plain RSA signature, PCR values, AK qualified name, and optional normalized event log. Provisioning refuses to overwrite occupied handles and saves a verified serialized AK handle rather than trusting a raw number. The independent verifier:

1. Parses the bounded binary quote and requires TPM generated magic and quote attestation type.
2. Matches the AK qualified signer and pre-registered AK public key/key ID.
3. Matches the quote extra data to the issued nonce and consumes that nonce once.
4. Verifies the RSASSA-SHA256 quote signature.
5. Requires the exact configured PCR selection and reconstructs the signed composite digest.
6. Replays normalized event digests into PCRs when an event log is supplied or required.
7. Applies freshness, expiry, and proof replay checks.

HardProof returns identity and measurement evidence only. Event Horizon policy and capability processes make the authorization decision.

## Deterministic fixtures

```bash
cd hardproof
npm install
npm run build
npm test
```

The fixture suite covers valid, tampered PCR, stale, replayed, wrong-AK, wrong-PCR, tampered/missing event-log, unknown/expired nonce, and missing-provider cases. These synthetic signed quotes test parser/verifier behavior but are not hardware evidence.

## `swtpm` command-path integration

On Linux with `swtpm`, `tpm2-tools`, Node, and npm installed:

```bash
./scripts/run-swtpm-hardproof.sh
```

The helper starts a temporary TPM 2.0 simulator, provisions a new AK without overwriting any existing material, enables the normally skipped integration test, and removes only its own `mktemp` directory. This exercises the real Linux tooling path but must not be labeled hardware-rooted operational evidence.

The 2026-07-24 reference run used `swtpm` 0.7.3 and `tpm2-tools` 5.6 and passed all 17 HardProof tests with no skip. The persistent-handle workflow fixed by that run follows the upstream `tpm2_createak`/`tpm2_evictcontrol` pattern.

## Real Linux TPM

Provision into a dedicated directory exactly once:

```bash
cd hardproof
HARDPROOF_REAL_TPM=1 \
HARDPROOF_TPM_WORKDIR=/var/lib/hardproof/ak \
HARDPROOF_TPM_PROVISION_AK=1 \
npm test
```

For later runs omit `HARDPROOF_TPM_PROVISION_AK`; the existing context, PEM public key, and qualified-name files are loaded. A non-device TCTI may be set with `HARDPROOF_TPM_TCTI`. A normalized event-log JSON file may be set with `HARDPROOF_TPM_EVENT_LOG_JSON`; entries have exactly `bank`, `pcr`, and hex `digest` fields.

Missing devices, tools, AK files, invalid quotes, or unavailable hardware deny verification. There is no production simulator fallback.
