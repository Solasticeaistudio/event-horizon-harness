# Reproducibility

## Preserve and inspect the baseline

The extracted archive was committed before changes as `2d7143e` and tagged `v0.3-baseline`. The source ZIP SHA-256 is:

```text
DE22CD55CB2A7C0E86A234EC24D5792EA7ED28CBA68873E42C859B2E6868EE12
```

Use `git diff v0.3-baseline..HEAD` to review all hardening changes.

## Clean dependency and build sequence

```bash
npm ci
python -m pip install -e .
npm run build
npm test
make demo
```

On Windows, use `./scripts/demo.ps1` instead of `make demo`. The exact verified counts are recorded in [STATUS.md](../STATUS.md); the real-TPM integration test is opt-in on a configured Linux host.

For a fresh temporary clone that repeats install, builds, tests, demo, fixed-vector, certificate, and repository-policy checks, run:

```bash
./scripts/verify-clean-install.sh
```

or on Windows PowerShell:

```powershell
./scripts/verify-clean-install.ps1
```

## Demonstrations

```bash
make demo
python -m event_horizon.process_demo --workdir .demo/process
python -m event_horizon.adversarial_demo --workdir .demo/adversarial
python scripts/run_firecracker_demo.py --fallback process
```

The public demo prints all seven process IDs, probes the hostile executor for credentials/private keys, proves one exact capability works once, proves replay/widening/egress fail, restarts the recorder, tears down the executor, and emits a signed certificate. Nonce and capability consumption use local durable SQLite state outside the hostile executor; replay remains denied across tested service restarts. The scripted adversarial demo must report all ten synthetic campaigns contained.

See `docs/ATTESTATION_TPM.md` and `docs/FIRECRACKER.md` before making TPM or VM-isolation claims.
