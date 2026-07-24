# Codex launch prompt

You are taking over the Event Horizon Harness v0.3 repository.

The mission is to turn the current process-level authority-containment proof into a reproducible compromise-tolerant research harness while preserving every existing invariant and test.

## Non-negotiable claim

Root or total compromise inside the hostile execution cell must not create transferable authority outside it.

The system must fail closed against:

- capability replay;
- scope or argument widening;
- cross-session transfer;
- cross-executor transfer;
- expiry bypass;
- ambient credentials;
- unrestricted egress;
- persistence after teardown;
- lateral movement;
- evidence tampering;
- one compromised guardian;
- signer or verifier unavailability.

## Existing baseline

Run first:

```bash
cd attestation
npm install
npm run build
npm test
cd ..
python -m pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m event_horizon.demo
```

Expected baseline: 7 Executor Attestation tests and 13 Event Horizon tests passing.

Do not remove or weaken tests to make changes pass.

## Priority 1: split trust domains

Separate into independent OS processes:

1. Neural Link Zero parser/canonicalizer
2. Guardian quorum
3. Executor Attestation verifier
4. Capability signer/broker
5. Sacrificial executor
6. External recorder
7. Certificate builder

Use a minimal length-prefixed canonical protocol. Avoid general HTTP in the trusted path. Reject unknown message types and fields. Add byte, nesting, deadline, and request-count limits.

## Priority 2: complete Executor Attestation TPM path

Implement Linux TPM 2.0 support first:

- explicit Attestation Key creation/loading;
- verifier-issued nonce;
- TPM quote over configured PCRs;
- TPMS_ATTEST parsing;
- quote signature verification;
- AK public-key registration;
- PCR digest reconstruction;
- event-log validation where available;
- fixtures for valid, tampered, stale, replayed, wrong-AK, and wrong-PCR proofs.

Do not silently fall back to simulator in production mode. Hardware failure must deny attestation.

Keep Executor Attestation authorization-free. It proves identity and measurements only.

## Priority 3: bind attestation throughout authority

The Event Horizon capability already contains a Executor Attestation attestation digest. Extend this so the executor verifies:

- attestation result digest;
- executor/device ID;
- image/measurement digest;
- verifier policy digest;
- capability signer key ID;
- exact request digest.

Move the capability private key into a signer process. The executor receives only the public key.

## Priority 4: real sacrificial cell

Create a Firecracker development target:

- read-only minimal root filesystem;
- ephemeral scratch disk;
- no package manager;
- no host mounts;
- no metadata endpoint;
- no cloud, Kubernetes, registry, or CI identity;
- no network device by default;
- fixed vsock protocol only;
- deterministic teardown and disk destruction;
- external watchdog.

First demonstrate deliberate guest root. Then show that root reveals no reusable authority.

## Priority 5: external evidence plane

Move authoritative recording outside the sacrificial host. Add:

- sequence numbers;
- hash chaining;
- signed receipts;
- loss and reordering detection;
- fixed-size telemetry envelopes;
- recorder restart recovery;
- tamper tests after simulated host compromise.

## Priority 6: Nemesis escape campaigns

Use the uploaded Nemesis concepts to build synthetic, owned scenarios only:

- fake metadata credential service;
- fake package proxy;
- fake neighboring workload;
- fake service account;
- fake internal API;
- writable local audit decoy;
- capability theft and replay;
- guardian compromise injection;
- session and executor substitution;
- output-channel pressure.

No real-world targets or unrestricted connectors belong in Black Hole mode.

## Required deliverables

- updated architecture and TCB inventory;
- runnable local process-separated demo;
- TPM simulator fixtures and real TPM integration path;
- Firecracker build scripts or a clearly isolated fallback when KVM is unavailable;
- expanded test suite;
- threat-model updates;
- reproducible commands;
- signed Containment Certificate containing attestation, capability, policy, image, recorder, teardown, and egress evidence.

Commit in small reviewable steps. Preserve the original v0.3 state in Git before beginning.
