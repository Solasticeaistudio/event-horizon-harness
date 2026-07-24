# Event Horizon Harness v0.3

Event Horizon is a compromise-tolerant authority-containment research harness. Its non-negotiable claim is:

> Root or total compromise inside the hostile execution cell must not create transferable authority outside it.

The original v0.3 archive is preserved by Git commit `2d7143e` and annotated tag `v0.3-baseline`. The current working line hardens that baseline without removing or weakening its tests.

## Implemented research harness

- Seven independent OS processes: parser/canonicalizer, Executor Attestation verifier, guardian quorum, signer/broker, sacrificial executor, external recorder, and certificate builder.
- A four-byte, big-endian, length-prefixed canonical JSON protocol with allowlisted messages and fields plus byte, string, collection, nesting, deadline, and request-count limits.
- One-use Ed25519 capabilities bound to the exact request, session, executor/device, image measurement, verified attestation result, verifier policy, static policy, and signer key ID.
- Signer isolation: only the signer process receives the capability private key; the executor receives its public key.
- An external evidence plane with sequence numbers, hash chaining, signed receipts, gap detection, restart recovery, and fail-closed tamper behavior.
- Signed evidence-complete Containment Certificates covering attestation, capability, policy, image, recorder, teardown, and egress.
- Independent TPM 2.0 quote parsing and verification, explicit Linux AK provisioning/loading, verifier nonces, PCR reconstruction, normalized event-log checking, and negative fixtures.
- A route-less Firecracker development target with a read-only rootfs, ephemeral scratch disk, no NIC or MMDS, fixed vsock, and an external teardown watchdog.
- Ten scripted synthetic adversarial campaigns. Fixtures use `synthetic://` endpoints and `EH-HONEY-*` tokens; the isolated mode has no unrestricted connectors.

## Verified status

- 36 Python Event Horizon tests pass, including every original test.
- 16 Node Executor Attestation tests pass; the 17th real-TPM test is skipped unless explicitly enabled.
- The original baseline remains reproducible: 13 Python tests and 7 Executor Attestation tests at `v0.3-baseline`.
- The opt-in Linux `swtpm` command-path run passes all 17 Executor Attestation tests; it validates integration but is explicitly not hardware provenance.

## Reproduce

```bash
python -m pip install -e .
cd attestation
npm install
npm run build
npm test
cd ..
PYTHONPATH=src python -W error::ResourceWarning -m unittest discover -s tests -v
PYTHONPATH=src python -m event_horizon.demo
PYTHONPATH=src python -m event_horizon.process_demo
PYTHONPATH=src python -m event_horizon.adversarial_demo
```

On PowerShell, set `$env:PYTHONPATH = "src"` before the Python commands. See [Reproducibility](docs/REPRODUCIBILITY.md), [TPM integration](docs/ATTESTATION_TPM.md), and [Firecracker target](docs/FIRECRACKER.md) for hardware-specific runs.

## Claim boundary

The process-separated demo proves authority separation and fail-closed behavior, not VM isolation. The Firecracker runner claims hardware isolation only after a real Linux KVM launch succeeds and the external watchdog records teardown. `swtpm` exercises the real TPM command path but is not hardware-rooted. Hardware or tool failure never falls back silently; it denies attestation. Executor Attestation supplies identity and measurement evidence only and never authorizes an action.
