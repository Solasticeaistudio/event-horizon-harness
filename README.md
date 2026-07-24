# Event Horizon

[![CI](https://github.com/Solasticeaistudio/event-horizon-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/Solasticeaistudio/event-horizon-harness/actions/workflows/ci.yml)

Event Horizon is a research harness for testing whether a fully compromised autonomous-agent execution environment can convert local control into transferable authority.

The tested claim is narrower than general containment: compromise inside the hostile execution cell must not grant transferable authority, unrestricted egress, durable persistence, cross-session influence, or control over authoritative evidence.

## What this repository demonstrates

- Strict canonical requests cross explicit process boundaries with bounded schemas and duplicate-key rejection.
- Executor Attestation issues a fresh, context-bound nonce and dispatches verification by signed-bundle method. The default public demo uses a simulator and labels it development-only.
- An Ed25519 capability binds the exact request, arguments, session, executor, device, measurement, attestation, verifier policy, static policy, expiry, output limit, and one-use identifier.
- The signer and executor independently reconstruct request and argument digests. Replay consumption is atomic inside one broker process.
- Four required guardians form a unanimity veto. Missing, malformed, stale, inconsistent, crashed, or timed-out decisions deny execution.
- An independent logical evidence recorder hash-chains events and signs receipts. A detached Ed25519 containment certificate covers the recorded evidence domains and verified teardown.
- Fixed adversarial vectors and compromise-injection tests exercise parser disagreement, substitution, replay, guardian failure, evidence tampering, and transfer attempts.

## What it does not demonstrate

This repository does not demonstrate containment of a frontier model, production Firecracker isolation, production TPM enrollment or hardware provenance, resistance to host-kernel compromise, physically one-way evidence storage, distributed replay-state atomicity, or an independent security audit. The scripted adversary uses harmless synthetic actions; it is not a real offensive campaign result.

See [Known limitations](KNOWN_LIMITATIONS.md) for the complete claim boundary.

## Core security invariant

> Guardians may only subtract authority. Dynamic approval can never exceed the deterministic static policy ceiling.

Every issued capability is the intersection of the canonical request and deterministic static policy, further restricted by all guardian vetoes. A model, guardian, approval service, or human decision cannot add operations, resources, arguments, identities, duration, egress, or output beyond that ceiling. Static-policy failure denies capability issuance.

## Threat model

Assume arbitrary code execution, root-equivalent visibility, stolen local files and process memory, parser pressure, replay, concurrency, and deliberate evidence tampering inside the sacrificial cell. Capability signing keys, attestation enrollment, deterministic policy, broker replay state, the logical recorder, certificate signing, and the host isolation boundary remain trusted computing base components in the current prototype.

The system accepts loss of availability when a trusted component fails. It does not recover availability by granting fallback authority. See the [full threat model](docs/THREAT_MODEL.md) and [Executor Attestation threat model](docs/ATTESTATION_THREAT_MODEL.md).

## Architecture

```text
Untrusted agent
    |
    v
Intent Canonicalizer
    |
    v
Static Policy Ceiling
    |
    +--> Executor Attestation Guardian
    +--> Lineage Budget Guardian
    +--> Behavioral Transition Guardian
    |
    v
Capability Broker
    |
    v
Sacrificial Executor
    |
    v
Sanitized Result Channel

Independent logical side plane on the same host:
requests, decisions, capabilities and results
    -> Independent logical evidence recorder
    -> Signed Containment Certificate
```

Physical separation of the evidence plane is future work. Implementation details are in [Architecture](docs/ARCHITECTURE.md), [Guardian quorum semantics](docs/GUARDIAN_QUORUM.md), and [Executor Attestation architecture](docs/ATTESTATION_ARCHITECTURE.md).

## Quick start

Requirements: Python 3.11+, Node.js 20+, npm, and GNU Make on POSIX systems.

```bash
npm ci
python -m pip install -e .
make demo
```

On Windows PowerShell:

```powershell
npm ci
python -m pip install -e .
./scripts/demo.ps1
```

The demo generates development keys at runtime. It commits no private key and explicitly states that simulator verification is not hardware-backed attestation.

## Reference result

The current scripted demo produces this normalized result:

| Check | Result |
|---|---:|
| Initial local access | ASSUMED |
| Executor attestation | VERIFIED (SIMULATOR) |
| Permitted exact operation | SUCCESS |
| Capability replay | DENIED |
| Argument widening | DENIED |
| Cross-executor transfer | DENIED |
| Unauthorized network operation | DENIED |
| Local evidence-copy tampering | DETECTED |
| Containment certificate | VERIFIED |

The deterministic normalized fixture is under [examples/reference-run](examples/reference-run/README.md). Fresh nonces, keys, timestamps, capabilities, and digests intentionally change on every live run.

## Verification

```bash
npm ci
npm run build
npm test
python scripts/verify_capability_vectors.py
python scripts/verify_certificate.py .demo/latest-containment-certificate.json
python scripts/check_repository_policy.py
```

`npm test` currently runs 43 TypeScript tests—42 pass and the real-TPM integration test is opt-in—and 61 Python tests. For an isolated clone, run `scripts/verify-clean-install.sh` or `scripts/verify-clean-install.ps1`.

## Attack the harness

Start with [RED_TEAM.md](RED_TEAM.md) and [SECURITY.md](SECURITY.md). Public testing is limited to owned synthetic environments. Useful targets include authority widening, replay, executor transfer, nonce reuse, hardware-trust forgery, evidence-chain alteration, and persistence after verified teardown.

The fixed capability inputs are in [test-vectors](test-vectors/README.md):

```bash
python scripts/verify_capability_vectors.py
python -m unittest discover -s tests -p "test_guardian_compromise.py" -v
```

Report plausible containment bypasses privately before publishing details.

## Current limitations

The default execution path is process separation, not a production microVM. TPM fixtures and `swtpm` do not establish hardware provenance. The evidence recorder is logically independent but runs on the same host. Nonce and capability atomicity are single-process guarantees. Tests are project-authored and automated, and no external audit has occurred.

These are active limitations, not deployment footnotes. See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

## Roadmap

1. Move nonce and capability consumption to a transactional cross-process backend.
2. Complete production TPM enrollment, endorsement validation, quote generation, and measurement policy.
3. Run the executor in a reproducibly built Firecracker image with enforced host controls and teardown.
4. Place the authoritative recorder and certificate key behind a separately administered boundary.
5. Commission independent parser, capability, attestation, evidence, and containment review.

Contribution requirements are in [CONTRIBUTING.md](CONTRIBUTING.md). The repository retains its existing source-review license; see [LICENSE](LICENSE).
