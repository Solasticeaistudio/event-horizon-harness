# Reference certificate fixture

The certificate in this directory is a deterministic signature-verification fixture. It makes no containment claim: it records no actions, labels itself `signature_fixture_only`, and contains only a public key and signature. The comprehensive synthetic reference run will replace it as the public demo is hardened.

Verify it with:

```bash
python scripts/verify_certificate.py examples/reference-run/containment-certificate.json
```
