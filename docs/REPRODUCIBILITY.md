# Reproducibility

## Preserve and inspect the baseline

The extracted archive was committed before changes as `2d7143e` and tagged `v0.3-baseline`. The source ZIP SHA-256 is:

```text
DE22CD55CB2A7C0E86A234EC24D5792EA7ED28CBA68873E42C859B2E6868EE12
```

Use `git diff v0.3-baseline..HEAD` to review all hardening changes. The repository has no configured remote; the tag is a local preservation point unless it is exported separately.

## Clean dependency and build sequence

```bash
python -m pip install -e .
cd hardproof
npm install
npm run build
npm test
cd ..
PYTHONPATH=src python -W error::ResourceWarning -m unittest discover -s tests -v
```

Expected on a host without a real TPM: 16 passing HardProof tests plus one skipped real-TPM integration test, and 36 passing Event Horizon tests.

## Demonstrations

```bash
PYTHONPATH=src python -m event_horizon.demo
PYTHONPATH=src python -m event_horizon.process_demo --workdir .demo/process
PYTHONPATH=src python -m event_horizon.nemesis_demo --workdir .demo/nemesis
python scripts/run_firecracker_demo.py --fallback process
```

The process demo prints all seven process IDs, probes the hostile executor for credentials/private keys, proves one exact capability works once, proves replay/widening/egress fail, restarts the recorder, tears down the executor, and emits a signed certificate. The Nemesis demo must report all ten campaigns contained.

See `docs/HARDPROOF_TPM.md` and `docs/FIRECRACKER.md` before making TPM or VM-isolation claims.
