# Event Horizon v0.4.0 release checklist

Release title: **Event Horizon v0.4.0 — Executor Attestation and Public-Artifact Hardening**

## Artifact identity and claims

- [x] Package and Python project versions are `0.4.0`.
- [x] Executor Attestation is the only active public subsystem name; the old mapping is confined to `docs/RENAMING_NOTES.md`.
- [x] Public component names are functional rather than mythological.
- [x] The README states the static-policy ceiling and distinguishes demonstrated behavior from non-claims.
- [x] Simulator output is labeled development-only and non-hardware-backed.
- [x] Firecracker, physical TPM provenance, frontier-model containment, production readiness, and independent audit are not claimed.
- [x] The existing proprietary source-review license declaration is preserved; this release is not described as open source.

## Security regressions

- [x] Provider-specific attestation verification derives trust from verifier output, not a bundle string.
- [x] Unknown/missing/malformed providers and invalid TPM evidence fail closed.
- [x] Every accepted attestation nonce is authority-issued, context-bound, durable, and atomically one-use across cooperating local verifier processes.
- [x] The authenticated remote replay interface passes signed Python/Node interoperability, concurrency, rollback, stale-primary, forgery, and outage conformance tests; documentation does not misrepresent its single-writer reference service as consensus.
- [x] Development attestation creates a fresh proof for every session and has no success cache.
- [x] Capability schemas, canonicalization, exact bindings, Ed25519 signatures, expiration, and durable cross-process replay checks pass.
- [x] Signer, recorder, and certificate mutations require audience-bound Ed25519 client authorization with durable one-use nonces.
- [x] Capability, recorder, and certificate seeds are absent from JSON configuration and survive restart through restricted development files.
- [x] Guardian compromise, timeout, malformed-output, stale-response, policy-version, and static-policy failure tests pass.
- [x] Demo replay, widening, executor transfer, prohibited egress, evidence tampering, teardown, and certificate checks pass.

## Reproducibility and hygiene

- [x] One root `package-lock.json` is committed and `npm ci` succeeds.
- [x] Python runtime dependencies, transitives, and build backend are pinned.
- [x] CycloneDX SBOM is committed at `artifacts/sbom.cdx.json`.
- [x] POSIX and PowerShell clean-install scripts use a temporary clone.
- [x] Repository policy rejects tracked dependency trees, generated builds, private keys, environment secrets, ZIP archives, oversized files, and active stale names.
- [x] No tracked private keys, `.env` secrets, generated ZIP archives, dependency trees, or build outputs were found.

## Verified locally on 2026-07-24

- [x] `npm ci`
- [x] `npm run build` for all eight TypeScript workspaces
- [x] 46 portable TypeScript tests passed; one real Linux TPM integration test skipped by design
- [x] 83 Python tests passed
- [x] All eight fixed capability vectors passed
- [x] PowerShell demo produced the documented result
- [x] Generated Ed25519 containment certificate verified independently
- [x] Python lint and repository-policy audit passed
- [x] Temporary clean-clone verification passed

## Publication actions requiring repository authority

- [ ] Push the release commit and observe hosted GitHub Actions.
- [ ] Create the `v0.4.0` tag.
- [ ] Publish `docs/releases/v0.4.0.md` as the GitHub Release body.

The unchecked publication actions are intentionally not performed by the local artifact-preparation workflow.
