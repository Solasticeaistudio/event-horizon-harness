# Status

## Completed

- Repository inventory completed; the initial worktree was clean.
- Renamed the subsystem, source tree, packages, public TypeScript APIs, Python provider, CLI, environment variables, integration tests, evidence fields, and active documentation to Executor Attestation.
- Added architecture, threat-model, verification, and concise renaming documents.
- Removed tracked generated JavaScript build products and the tracked dependency tree encountered during the namespace migration.
- Regenerated the attestation lockfile with only current workspace paths.
- Removed archived ZIP/checksum releases, generated output snapshots, stale source inventories, recovered build notes, and AI-development handoff material from the public tree.
- Expanded the root ignore policy across all Python and Node workspaces, local environment files, coverage output, and internal development material.
- Promoted npm to a pinned root workspace with one lockfile and root-level build/test commands.
- Pinned the Python runtime dependency and build backend for the v0.4.0 artifact.
- Generated a deterministic CycloneDX 1.5 SBOM with 54 Node and pinned Python components.
- Added isolated clean-install scripts for POSIX shells and PowerShell.
- Added an independently verifiable, explicitly non-claiming certificate fixture.
- Replaced public mythology-based component labels with functional names in documentation, tests, evidence IDs, console output, and entry points.
- Renamed the public intent-canonicalization and scripted-adversarial modules while keeping behavior unchanged.
- Replaced caller-controlled trust mapping with a registered provider-verifier dispatch boundary.
- Restricted simulator verification to development trust and enforced strict provider-result schemas.
- Added TPM quote-signature plus whole-bundle attestation-key signature verification before hardware trust.
- Replaced nonce equality checks with an authority-owned state machine and atomic one-use transition.
- Bound every issued challenge to device, executor, session, purpose, issuance time, and expiration time.
- Added in-memory and SQLite nonce persistence implementations behind one atomic transition interface.
- Added durable SQLite capability consumption behind a shared broker/executor interface, with separate authority and executor domains.
- Wired the default local and process-separated harnesses to durable replay state; authoritative nonce and broker state is not configured into the hostile executor.
- Added process restart, 24-process nonce contention, 16-process capability contention, namespace/domain isolation, corruption, collision, closed-store, and schema-version regressions.
- Added Ed25519-authenticated request envelopes for capability issue/consume, evidence append, and containment-certificate construction.
- Bound each protected authorization to the exact canonical RPC envelope, service audience, client key, freshness window, and a durable one-use nonce.
- Removed inline capability/recorder seeds from service JSON, made the certificate key restart-stable, and provisioned distinct restricted development key files.
- Added 16-process protected-request contention plus replay, mutation, wrong-key, wrong-audience, algorithm, signature, expiry, future-time, unavailable/corrupt/schema-incompatible state, collision, key-file, unauthenticated-service, and restart-continuity tests.
- Propagated verified nonce context and lifetime through guardians, capabilities, process services, and evidence records.
- Made the development bridge's no-cache contract explicit: each capability request requires a fresh proof and session-bound result digest.
- Added stale-proof and reuse regressions covering expiry, measurement, policy, session, key, and executor changes.
- Restricted security-sensitive request values to strict, bounded, NFC canonical JSON with interoperable integers and no floating point.
- Made request arguments recursively immutable and required the signer and executor verifier to reconstruct request and argument digests independently.
- Added strict Ed25519 envelope, key-identity, signature-encoding, integer-time, exclusive-expiration, clock-skew, and atomic replay checks.
- Added eight fixed public capability vectors and adversarial tests for parser disagreement, substitution, mutation, replay, and TOCTOU behavior.
- Enforced required guardian identities, one response per guardian, canonical request binding, and consistent static-policy versions.
- Converted guardian exceptions, malformed responses, missing responses, and timeouts into explicit veto decisions.
- Added compromise-injection coverage and exact unanimity/veto semantics documentation.
- Added the repository's existing proprietary license declaration, private security-reporting policy, safe red-team guide, known-limitations ledger, contribution guide, changelog, and citation metadata.
- Added clean Python, TypeScript, integration, evidence, certificate, fixed-vector, and repository-policy GitHub Actions jobs.
- Added dependency-free Python linting plus tracked-artifact, private-key, large-file, environment-file, archive, and stale-name enforcement.
- Added `make demo` and `scripts/demo.ps1` for a single process-separated containment demonstration with the required concise summary.
- The demo now exercises fresh simulator attestation, exact capability use, replay, argument and executor transfer, prohibited egress, evidence tampering, verified teardown, and an independently verified live certificate.
- Added a deterministic normalized reference result while keeping fresh per-run keys, nonces, timestamps, and digests out of version control.
- Replaced the prototype README with a concise technical-review entry point, actual demo results, measured claim boundaries, functional architecture, verification commands, and CI badge.
- Added the safe `AdversarialRunner` interface, explicit synthetic campaign manifest, strict budget schema, declared-range validation, deterministic transcript replay, and human approval gate for non-simulated adapters.
- Added a harmless five-step scripted adversary with no URLs, IP addresses, public-network destinations, raw commands, credentials with authority, or real infrastructure connectors.
- Added a strict paired experiment format for `baseline` and `event-horizon` modes with deterministic scripted data and explicit unmeasured fields.
- Added an implementation-level design defense covering the authority ceiling, signed bindings, replay controls, attestation trust, TCB attacks, parser disagreement, evidence, and deployment gaps.
- Added a strict signed cross-language replay protocol with per-client operation/partition policy, freshness, exact request/response binding, pinned server keys, explicit epochs, and monotonic hash-chain checkpoints.
- Added a single-writer Python reference replay service with an HTTP binding plus remote capability-consumption and protected-request-authorization adapters.
- Made the Executor Attestation nonce persistence boundary, nonce authority, verifier, SDK, service, bridge, and tests awaitable; added a fail-closed TypeScript remote nonce adapter and HTTP client.
- Added 48-way remote redemption contention, client-policy isolation, collision, nonce-context, request forgery, unknown-field, response forgery/swapping, rollback, fork-ahead, failover with key rotation, stale-primary, unsafe-promotion, outage, and HTTP conformance tests.
- Added a live Python-service/Node-client interoperability check covering canonical JSON, Ed25519 key IDs and signatures, nonce transitions, response binding, and checkpoints.
- Fixed the isolated Python CI job by installing and building the three Executor Attestation workspaces required by the Python verifier bridge before running Python tests.
- Replaced unbounded TypeScript replay-response buffering with a 65,536-byte raw streaming bound, early `Content-Length` rejection, incremental UTF-8 decoding, and immediate reader cancellation.
- Made TypeScript `adoptEpoch()` asynchronous and serialized epoch, key, transport, and checkpoint adoption with every signed remote operation.
- Added one shared checkpoint-state validator for construction and adoption, requiring epoch-specific genesis at checkpoint zero and an explicit digest for restored nonzero checkpoints.
- Aligned the Python replay client and empty-service promotion behavior with the same unambiguous genesis and restored-checkpoint rules.
- Added deterministic streaming, cancellation, queue recovery, adoption ordering, atomic validation, and restored-state regression coverage.

## Tests executed

- `npm ci`: passed with 0 reported dependency vulnerabilities.
- `npm run build`: passed for all eight TypeScript workspaces.
- `npm run typecheck`: passed for all eight TypeScript workspaces.
- `npm test`: 62 TypeScript tests passed, one opt-in real Linux TPM test skipped, the Python-service/Node-client replay interoperability check passed, and 99 Python tests passed.
- `python -m unittest discover -s tests -v`: 99 passed.
- `python scripts/verify_remote_replay_interop.py`: passed against the live Python HTTP service and Node client.
- CI-equivalent public demo, evidence-chain verification, containment-certificate verification, and selected fixed-vector verification: passed.
- `scripts/demo.ps1`: passed with the documented success, denial, detection, and certificate summary.
- GNU Make was not installed on the Windows release host; the documented PowerShell-equivalent demo command passed.
- Live certificate verification: passed with Ed25519 key-identity validation.
- Fixed capability vectors: 8 of 8 passed.
- Python lint: passed for all 52 tracked Python files.
- Repository policy: passed for all 176 tracked paths after staging the new sources.
- Temporary clean-clone install, build, tests, demo, vectors, fixture certificate, and policy audit: passed.

## Known failures

- None in the portable release suite.
- The real Linux TPM integration test is opt-in and was not run on the Windows release host; this is a declared unverified integration target, not a passing hardware-attestation claim.
- Hosted GitHub Actions cannot be observed until the local release commit is pushed.

## Security limitations

- SQLite nonce and capability consumption is durable and atomic across cooperating processes using one local database on one host. The authenticated remote interface defines linearizable transitions and detects rollback relative to client-retained signed checkpoints, but its reference service is single-writer: no consensus, old-leader fencing, rollback-resistant client storage, or deployed multi-host guarantee is claimed.
- The execution cell is not a production Firecracker deployment.
- The simulator is development-only and is not hardware attestation.
- The authoritative replay database, WAL, containing directory, configuration, backups, and rollback protection remain trusted. Deletion or restoration of old state can erase consumption history, and records are not yet compacted. The portable same-user process fallback does not enforce filesystem isolation between executor and authority paths.
- TPM enrollment, endorsement validation, physical provenance, and fleet measurement policy are incomplete.
- Signer, recorder, and certificate mutations are authenticated, and their private seeds are outside JSON configuration, but the development harness provisions all clients, services, files, and storage under one host account. It is not independently administered, HSM-backed, physically one-way, or protected from same-user process/file access. Authentication does not make a dishonest authorized coordinator truthful.
- Tests are project-authored and automated; no external security audit has occurred.
- No frontier-model containment claim is made.

## Files changed

- `attestation/` (moved from the prototype directory and renamed throughout)
- `docs/ATTESTATION_ARCHITECTURE.md`
- `docs/ATTESTATION_THREAT_MODEL.md`
- `docs/ATTESTATION_VERIFICATION.md`
- `docs/RENAMING_NOTES.md`
- Python integration, certificate schema, scripts, and active documentation references
- Root `.gitignore` and removal of obsolete public-tree debris
- Root `package.json` and `package-lock.json`
- `artifacts/sbom.cdx.json`
- `scripts/verify-clean-install.sh` and `scripts/verify-clean-install.ps1`
- `scripts/verify_certificate.py`
- `examples/reference-run/`
- `pyproject.toml`
- Functional component IDs, intent canonicalizer, scripted adversarial runner, public architecture, and integration output
- Attestation provider-verifier interfaces, simulator and TPM verifier implementations, Linux TPM bundle signing, and adversarial dispatch tests
- Attestation nonce authority, persistence interface, verifier call sites, process-boundary context binding, and concurrency tests
- SQLite nonce persistence, Python capability consumption store, process-harness wiring, multi-process/restart tests, and `docs/REPLAY_STATE.md`
- Protected-request authentication and replay state, restricted key provisioning, signer/recorder/certificate service wiring, compromise tests, and `docs/PROTECTED_BOUNDARIES.md`
- Bounded synthetic adversarial-runner interface, manifest schema, safe adapter, public example, documentation, and regression tests
- Paired experiment validator, JSON schema, explicitly scripted reference comparison, documentation, and tests
- `docs/DESIGN_DEFENSE.md`
- `src/event_horizon/remote_replay.py`, Python replay conformance tests, and Python remote adapters
- Awaitable Executor Attestation nonce/verifier APIs and `RemoteNoncePersistence`
- `docs/REMOTE_REPLAY_PROTOCOL.md` and cross-language replay verification scripts
- `attestation/packages/core/src/remote-nonce-persistence.ts`
- `attestation/tests/remote-http-transport.test.mjs` and `attestation/tests/remote-replay-client-state.test.mjs`
- `.github/workflows/ci.yml`, `package.json`, `CHANGELOG.md`, and remote replay fixtures
- `RELEASE_CHECKLIST.md` and `docs/releases/v0.4.0.md`
- `STATUS.md`

## Commands to reproduce

```powershell
./scripts/verify-clean-install.ps1
./scripts/demo.ps1
python scripts/verify_certificate.py .demo/latest-containment-certificate.json
```

## Next engineering milestone

Deploy the authenticated replay interface on a consensus-backed replicated state machine with old-leader fencing, rollback-resistant client checkpoint storage, separately administered keys, TLS, monitoring, and backup/restore drills.

## Exact next command

```powershell
./scripts/verify-clean-install.ps1
```
