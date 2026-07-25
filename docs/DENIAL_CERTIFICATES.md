# Denial certificates

A denial certificate is a portable Ed25519-signed receipt for one evaluated request or attack attempt. It proves only that the identified attempt was evaluated with the listed build, policy, trust, guardian, decay, and evidence state. It does not prove that every variation would fail.

The strict v1 schema binds certificate/attempt/campaign/task/session identity, a hashed workload identity, technique, exact and canonical request digests, requested and effective authority, reason, policy-ceiling and provider-attestation digests, synthesizer/compiler versions, guardian and decay state, source revision/build/environment, evidence-chain root and signed recorder receipt, timestamp, signer identity, effect state, and whether no effect is known.

Effect states are explicit:

- `denied-before-effect` and `denied-after-validation`: `known_no_effect` is true.
- `effect-committed-response-lost`: `known_no_effect` is false.
- `indeterminate-crash` and `reconciliation-required`: `known_no_effect` is null.

The builder refuses a definitive no-effect claim for an ambiguous or committed state. The verifier checks the strict schema, canonical signed bytes, signer identity/revocation, certificate-ID replay, every digest, the embedded recorder receipt, recorder trust, and exact evidence-root linkage. Secret-like keys in requested/effective authority are rejected rather than copied into a certificate.

Verification requires explicit trust anchors:

```bash
eh-verify-denial certificate.json --trusted-signer signer-public.pem \
  --trusted-recorder recorder-public.pem
```

The Makefile equivalent is `make verify-denial CERT=certificate.json TRUSTED_SIGNER=signer-public.pem TRUSTED_RECORDER=recorder-public.pem`.
