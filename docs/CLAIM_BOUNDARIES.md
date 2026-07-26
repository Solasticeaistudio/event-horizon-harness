# Claim boundaries

Event Horizon is a research harness. Its supported claim is that, under the documented trusted-computing-base and process-isolation assumptions, tested hostile requests are mechanically constrained by a deterministic policy ceiling and cryptographically bound capabilities.

The adaptive synthesizer proposes a ceiling; it is not an authorizer and cannot mint or sign capabilities. The trusted compiler intersects proposals with global, tenant, environment, attestation, guardian, policy, and decay authority. A denial certificate records one evaluated denial and does not prove that every related attack would fail.

This repository does not claim unbreakability, production readiness, frontier-model containment, physical isolation, consensus, hardware-backed attestation, physical one-way evidence, or independent audit. The hardware switch is simulated, the default adversary is synthetic, and TLC is optional. See [Known limitations](../KNOWN_LIMITATIONS.md) and the technical report.
