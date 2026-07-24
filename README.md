# Event Horizon Harness v0.3

Event Horizon is a compromise-tolerant containment research harness for autonomous agents.

Its central claim is intentionally narrower and stronger than “the sandbox cannot be escaped”:

> Complete compromise of the agent workload must not grant transferable authority, unrestricted egress, durable persistence, cross-session influence, or control over authoritative evidence.

v0.3 combines the original authority-containment prototype with a clean-room rebuild of **HardProof**, the hardware-attestation SDK whose original repository was lost.

## What works now

### Event Horizon

- Strict typed action requests with unknown-field rejection
- Neural Link Zero with no direct execution authority
- Deny-by-default Cerberus policy evaluation
- Guardian quorum where any veto blocks
- Aegis lineage-wide request and denial budgets
- Talos prohibited-transition vetoes
- Ed25519-signed, short-lived, one-use capabilities
- Exact binding to session, agent, executor, operation, resource, arguments, policy, executor measurement, and HardProof attestation digest
- Replay, widening, cross-session, cross-executor, expiry, malformed-request, permissive-guardian, and recorder-tampering tests
- External append-only hash-chained recorder
- Ed25519-signed Containment Certificate
- Synthetic honey credential and assumed-root demonstration

### HardProof rebuild

- TypeScript monorepo with `crypto`, `core`, `simulator`, `prover-tpm`, `sdk`, `middleware`, `cli`, and development `cloud` packages
- Deterministic simulator prover
- Ed25519 proof signatures and canonical bundles
- Device-key registry
- Nonce issuance and one-time consumption
- Proof replay detection
- Freshness and expiry checks
- Exact PCR-style measurement policies
- Local `Client.prove()` and `Server.verify()` APIs
- Typed events and actionable `HardproofError` values
- Bundle encoding and middleware
- Event Horizon development verifier bridge

## Verified test status

- **13 Python Event Horizon tests passing**
- **7 Node HardProof tests passing**
- **20 total tests passing**

See `TEST_RESULTS.txt` and `hardproof/TEST_RESULTS.txt`.

## Run the complete harness

### Linux/macOS

```bash
python -m pip install -e .
cd hardproof
npm install
npm run build
npm test
cd ..
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m event_horizon.demo
```

### Windows PowerShell

```powershell
python -m pip install -e .
Set-Location hardproof
npm install
npm run build
npm test
Set-Location ..
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python -m event_horizon.demo
```

Precompiled JavaScript and a minimal vendored runtime are included so the development HardProof bridge can run immediately. Rebuilding TypeScript requires `npm install`.

## Important limits

This package does **not yet claim hardware isolation or production TPM attestation**.

The current HardProof path uses a deterministic simulator with real asymmetric signatures, freshness, replay protection, and measurement policy. The TPM package detects hardware and defines the provider boundary, but deliberately fails closed until platform-specific quote generation and independent quote verification are completed.

The execution cell is still simulated. The next major stage is a route-less Firecracker cell, separate verifier/signer/recorder processes, and a Nemesis-driven synthetic escape range.

## Start here tomorrow

Give Codex the repository and the contents of:

- `docs/CODEX_LAUNCH_PROMPT.md`
- `docs/CODEX_HANDOFF.md`
- `hardproof/docs/REBUILD_STATUS.md`
- `hardproof/docs/EVENT_HORIZON_INTEGRATION.md`

The immediate target is to turn this process-level proof into an independently separated containment system without weakening the existing 20-test baseline.
