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
- Generated a deterministic CycloneDX 1.5 SBOM with 15 Node and pinned Python components.
- Added isolated clean-install scripts for POSIX shells and PowerShell.
- Added an independently verifiable, explicitly non-claiming certificate fixture.
- Replaced public mythology-based component labels with functional names in documentation, tests, evidence IDs, console output, and entry points.
- Renamed the public intent-canonicalization and scripted-adversarial modules while keeping behavior unchanged.
- Replaced caller-controlled trust mapping with a registered provider-verifier dispatch boundary.
- Restricted simulator verification to development trust and enforced strict provider-result schemas.
- Added TPM quote-signature plus whole-bundle attestation-key signature verification before hardware trust.
- Replaced nonce equality checks with an authority-owned state machine and atomic one-use transition.
- Bound every issued challenge to device, executor, session, purpose, issuance time, and expiration time.
- Added an in-memory persistence implementation plus an explicit transactional persistence boundary without claiming distributed atomicity.
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

## Tests executed

- `npm ci`: passed with 0 reported dependency vulnerabilities.
- `npm run build`: passed for all eight TypeScript workspaces.
- `npm test`: 42 TypeScript tests passed, one opt-in real Linux TPM test skipped, and 70 Python tests passed.
- `python -m unittest discover -s tests -v`: 70 passed.
- `scripts/demo.ps1`: passed with the documented success, denial, detection, and certificate summary.
- GNU Make was not installed on the Windows release host; the documented PowerShell-equivalent demo command passed.
- Live certificate verification: passed with Ed25519 key-identity validation.
- Fixed capability vectors: 8 of 8 passed.
- Python lint: passed for 45 tracked Python files.
- Repository policy: passed for all 158 tracked paths.
- Temporary clean-clone install, build, tests, demo, vectors, fixture certificate, and policy audit: passed.

## Known failures

- None in the portable release suite.
- The real Linux TPM integration test is opt-in and was not run on the Windows release host; this is a declared unverified integration target, not a passing hardware-attestation claim.
- Hosted GitHub Actions cannot be observed until the local release commit is pushed.

## Security limitations

- Nonce atomicity is currently guaranteed only inside one verifier process; no Redis or transactional database backend ships yet.
- The execution cell is not a production Firecracker deployment.
- The simulator is development-only and is not hardware attestation.
- Capability consumption is process-local and not durable across broker state loss.
- TPM enrollment, endorsement validation, physical provenance, and fleet measurement policy are incomplete.
- The evidence recorder is logically separate but remains on the same host; it is not physically one-way or independently administered.
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
- Bounded synthetic adversarial-runner interface, manifest schema, safe adapter, public example, documentation, and regression tests
- Paired experiment validator, JSON schema, explicitly scripted reference comparison, documentation, and tests
- `docs/DESIGN_DEFENSE.md`
- `RELEASE_CHECKLIST.md` and `docs/releases/v0.4.0.md`
- `STATUS.md`

## Commands to reproduce

```powershell
./scripts/verify-clean-install.ps1
./scripts/demo.ps1
python scripts/verify_certificate.py .demo/latest-containment-certificate.json
```

## Next engineering milestone

Implement durable transactional nonce and capability consumption across verifier and broker replicas.

## Exact next command

```powershell
npm test
```
