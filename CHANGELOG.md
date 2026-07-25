# Changelog

All notable public-artifact changes are recorded here. The project follows semantic versioning for artifact releases; research claims remain limited to documented tests and topology.

## [Unreleased]

### Added

- A signed cross-language replay state-machine protocol with authorized operation/partition policies, pinned service epochs, monotonic hash-chain checkpoints, explicit failover adoption, and fail-closed HTTP clients.
- A single-writer Python reference service plus Python capability/protected-request adapters and an awaitable TypeScript Executor Attestation nonce adapter.
- Conformance coverage for concurrency, collisions, request and response forgery, response swapping, rollback, stale primaries, unsafe promotion, outages, and real Python-service/Node-client interoperability.

### Changed

- Made Executor Attestation nonce persistence, nonce authority operations, and verification awaitable so remote atomic transitions do not require blocking network I/O.

## [0.4.0] - 2026-07-24

### Added

- Provider-specific Executor Attestation verification with strict simulator and TPM trust separation.
- Context-bound, atomic one-use nonce authority and concurrency tests.
- Durable SQLite nonce and capability consumption across cooperating local verifier and broker processes, including restart, contention, corruption, and schema-version tests.
- Ed25519-authenticated signer, recorder, and certificate mutation requests with durable one-use authorization nonces.
- Restricted file-backed development keys for capability, receipt, and certificate signing, with restart continuity and no inline private seeds.
- Fresh per-session development attestation with no executor-ID success cache.
- Strict capability schemas, canonicalization defenses, public verification vectors, and atomic replay tests.
- Guardian compromise and coordination-failure injection tests.
- Reproducible root npm workspace, lockfile, SBOM, and clean-install verification scripts.
- Public architecture, threat-model, disclosure, red-team, contribution, and limitations documentation.
- A process-separated single-command containment demo with independent certificate verification.
- A bounded synthetic adversarial-runner interface and strict paired experiment format.
- Implementation-level design-defense answers and clean GitHub Actions regression workflows.

### Changed

- Renamed the attestation subsystem and public APIs to descriptive Executor Attestation terminology.
- Replaced mythology-based public labels with functional component names.
- Converted capability timestamps to integer Unix milliseconds with exclusive expiration.
- Aligned the importable Python package version with the `0.4.0` project metadata.

### Removed

- Tracked dependency trees, generated build output, embedded release archives, and internal development debris.

## [0.3.0] - 2026-07-24

- Initial authority-containment research prototype and process-separated demonstration.

[0.4.0]: https://github.com/Solasticeaistudio/event-horizon-harness/compare/v0.3-baseline...v0.4.0
[0.3.0]: https://github.com/Solasticeaistudio/event-horizon-harness/releases/tag/v0.3-baseline
