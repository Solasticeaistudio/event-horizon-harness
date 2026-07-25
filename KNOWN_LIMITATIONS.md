# Known limitations

Event Horizon is a research harness, not a production containment system.

- The execution cell is not yet a production Firecracker deployment. The process-separated path is the reproducible default; Linux/KVM integration remains a development target with host kernel, KVM, Firecracker, image, and watchdog assumptions.
- TPM quote generation and independent verification remain incomplete for a production deployment. Synthetic fixtures and `swtpm` exercise code paths but do not establish physical hardware provenance, endorsement, fleet enrollment, or production measurement policy.
- The Executor Attestation simulator does not constitute hardware attestation and can produce only development trust.
- The capability signer, evidence recorder, and certificate signer require authenticated mutation requests and use separate restricted key files, but the development harness provisions them under one host account. They are not independently administered, HSM-backed, physically one-way, or independently hosted. A same-user or host-kernel compromise remains inside the trusted computing base.
- SQLite-backed nonce and capability consumption is durable and atomic across cooperating processes on one host. It is not a multi-host or network-filesystem guarantee; database deletion, rollback, filesystem compromise, namespace/domain misconfiguration, and unbounded record retention remain security and operational limitations. In the portable same-user process fallback, keeping the authority path out of executor configuration is logical separation rather than enforced filesystem isolation.
- Tests are currently authored by the project creator and automated tooling. They are not independent validation.
- No claim is made that a frontier model has been contained. The demonstrations use deterministic synthetic actions and a harmless scripted adversary.
- No external security audit has occurred.
- The current certificate verifies claims over the recorder's evidence and configured teardown path; it does not make false evidence impossible when the recorder host or signing boundary is compromised.
- Protected request authentication identifies the configured coordinator client; it does not make an authorized but dishonest coordinator or evidence source truthful. Per-source independently administered recorder credentials are not implemented.
- Availability is intentionally sacrificed on verifier, signer, recorder, static-policy, guardian, or infrastructure failure.

These limitations are security-relevant. Results should not be generalized beyond the tested topology and explicit trust assumptions.
