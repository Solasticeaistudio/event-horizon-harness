# Codex handoff — Event Horizon Harness v0.3

## Current state

v0.3 is a runnable two-language proof:

- Python implements the Event Horizon authority path.
- TypeScript implements the rebuilt HardProof local attestation path.
- Event Horizon invokes the independent HardProof verifier bridge, records its evidence, and binds the proof digest into the one-use capability.
- Capability and Containment Certificate signatures use Ed25519.
- 20 total tests pass.

## Highest-priority engineering tasks

1. Preserve the repository in Git and push a remote before editing.
2. Split Neural Link Zero, guardians, verifier, signer, executor, recorder, and certificate builder into separate processes.
3. Replace the development subprocess bridge with a fixed local attestation protocol.
4. Implement and independently test the Linux TPM 2.0 provider.
5. Ensure the executor receives only verification keys, never signing keys.
6. Build the route-less Firecracker execution cell.
7. Move the recorder to a separate trust domain.
8. Add compromise injection at every boundary.
9. Turn Nemesis planning/replay modules into synthetic escape campaigns.
10. Integrate Iaso remediation replay through Event Horizon capabilities.

## Acceptance criteria for v0.4

- Existing 20 tests remain green.
- Process separation is demonstrated.
- A nonce-bound TPM quote can be generated and verified, or the hardware test is explicitly skipped when no TPM is present while simulator conformance remains green.
- A copied capability cannot be replayed, widened, transferred, or used after expiry.
- A route-less guest-root demo exposes no ambient credential or useful network path.
- The authoritative recorder survives hostile local tampering.
- The Containment Certificate includes HardProof evidence and verifies with a detached public key.
