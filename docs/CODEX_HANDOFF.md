# Codex handoff — current hardened working line

The original Event Horizon Harness v0.3 archive is preserved as commit `2d7143e` and annotated tag `v0.3-baseline`. Do not move or delete that tag. The archive SHA-256 is recorded in `docs/REPRODUCIBILITY.md`.

## Current state

- Seven process-separated trust domains use a strict canonical length-prefixed protocol.
- Capability authority is bound through attestation, verifier/static policy, signer, exact request, executor/device, image measurement, expiry, invocation, and output envelope.
- Linux TPM 2.0 quote acquisition and independent verification are implemented with explicit AK lifecycle and no production simulator fallback.
- Firecracker Linux/KVM build/run/watchdog assets are present; non-KVM fallback is explicit and cannot claim hardware isolation.
- The external recorder provides exact-size records, global/source sequence checking, hash chaining, Ed25519 receipts, restart recovery, and fail-closed tamper handling.
- Ten synthetic Nemesis campaigns cover fake services/credentials, audit tampering, replay, guardian compromise, substitution, and output pressure.
- Signed v0.4 Containment Certificates bind all required evidence domains.

## Verified commands

```bash
cd attestation
npm install
npm run build
npm test
cd ..
python -m pip install -e .
PYTHONPATH=src python -W error::ResourceWarning -m unittest discover -s tests -v
PYTHONPATH=src python -m event_horizon.process_demo
PYTHONPATH=src python -m event_horizon.nemesis_demo
```

Expected without hardware: 16 Executor Attestation tests pass, one real-TPM test skips, and all 36 Python tests pass.

## Honest limitations

- A real Firecracker 1.15.1 nested-KVM run succeeded under WSL2 and is recorded in `firecracker/fixtures/wsl2-nested-kvm-run.json`. It proves the development target executes, but is not a production jailer/host-hardening claim.
- The Linux TPM command path passed all 17 tests against `swtpm` 0.7.3 and `tpm2-tools` 5.6. This validates tooling integration but is not physical TPM provenance; no physical TPM was available on this host.
- The process demo shares a host kernel and is not a microVM isolation proof.
- Production recorder/key administration must be physically or administratively outside the sacrificial host; the local demo represents that boundary with independent processes.
- Normalized event-log checking is implemented, but production policy must provide and require a platform event log when available.

Start with `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/ATTESTATION_TPM.md`, `docs/FIRECRACKER.md`, and `docs/REPRODUCIBILITY.md`.
