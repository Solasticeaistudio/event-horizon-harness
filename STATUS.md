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
- Generated a CycloneDX 1.5 SBOM with 11 components.
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

## Tests executed

- `npm run build` in `attestation/`: passed for all 8 workspaces.
- `npm test` in `attestation/`: 16 passed, 1 skipped (opt-in real TPM).
- `eh-attest prove`, `eh-attest verify`, `eh-attest inspect`: passed.
- `python -m unittest discover -s tests -v`: 36 passed.
- Tracked-artifact and public-reader-path audits: passed.
- Prospective clean checkout: `npm ci`, Python virtual-environment install, all builds, all tests, demo, and certificate verification passed.
- Functional-label regression: 16 TypeScript tests passed, 1 opt-in TPM test skipped, 36 Python tests passed, and the scripted adversarial demo passed.
- Provider-dispatch regression: 26 TypeScript tests passed, 1 opt-in real-TPM test skipped, 36 Python tests passed, and all 8 TypeScript workspaces built.
- Nonce-authority regression: 34 TypeScript tests passed, 1 opt-in real-TPM test skipped, and 36 Python tests passed.
- Fresh-attestation regression: 42 TypeScript tests passed, 1 opt-in real-TPM test skipped, and 37 Python tests passed.
- Capability hardening regression: 51 Python tests passed, including all 8 fixed public vectors.

## Known failures

- None.

## Security limitations

- Nonce atomicity is currently guaranteed only inside one verifier process; no Redis or transactional database backend ships yet.
- The execution cell is not a production Firecracker deployment.
- The simulator is development-only and is not hardware attestation.

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
- `STATUS.md`

## Commands to reproduce

```powershell
npm ci
npm run build
npm test
python scripts/verify_certificate.py examples/reference-run/containment-certificate.json
```

## Next engineering milestone

Inject guardian compromise, malformed responses, timeouts, crashes, replay, and inconsistent-policy failures.

## Exact next command

```powershell
npm test
```
