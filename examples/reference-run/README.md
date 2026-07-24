# Deterministic reference result

`expected-summary.txt` and `reference-result.json` are the normalized, deterministic result contract for the harmless scripted public demo. They accurately label the Executor Attestation provider as a simulator and are not a captured frontier-model or hardware-attestation result.

The live demo generates fresh nonces, capabilities, Ed25519 keys, evidence timestamps, and digests, so those values intentionally differ on every run. Its latest certificate is written to `.demo/latest-containment-certificate.json` and can be checked independently:

```bash
python scripts/verify_certificate.py .demo/latest-containment-certificate.json
```

The committed `containment-certificate.json` remains a deterministic, zero-authority signature-verification fixture for clean-install checks. It makes no containment claim and commits no private key.
