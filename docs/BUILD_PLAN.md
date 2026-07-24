# Build plan

## Stage 0 — complete in v0.2

- Threat model and falsifiable invariants
- Minimal Neural Link Zero
- Static policy guardian
- Attestation measurement binding placeholder
- Lineage budget and sequence veto guardians
- One-use exact capabilities
- External hash-chain prototype
- Containment Certificate prototype
- Local compromise demonstrations and regression tests

## Stage 1 — process isolation

Separate all trusted components and fuzz every protocol boundary. Add property-based and differential canonicalization tests.

## Stage 2 — microVM isolation

Route-less Firecracker cell, read-only image, no ambient identity, vsock protocol, deterministic teardown.

## Stage 3 — host-compromise experiment

Deliberately grant host root on an authority-empty bare-metal worker. Verify no route, signer, recorder, credential, neighbor, or persistent state becomes reachable.

## Stage 4 — physical and hardware-backed controls

Separate guardian appliance, TPM/enclave attestation, asymmetric signing, one-way telemetry, fixed output envelopes, external watchdog.

## Stage 5 — frontier-agent evaluation

Run standard frontier agents, local open-weight agents, scripted adversaries, compromise injectors, and approved cyber-capable models against the same range and scoring rubric.

## Stage 6 — public research artifact

Open synthetic range, reproducible images, technical report, signed evidence bundles, limitations, benchmark scorecards, and independent review.


## v0.3 completion note

The simulator-backed Executor Attestation path, Ed25519 capability signing, Ed25519 certificate signing, attestation-digest capability binding, and combined Python/Node test baseline are complete. The next gate is process separation and real TPM quote verification.
