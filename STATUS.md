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

## Tests executed

- `npm run build` in `attestation/`: passed for all 8 workspaces.
- `npm test` in `attestation/`: 16 passed, 1 skipped (opt-in real TPM).
- `eh-attest prove`, `eh-attest verify`, `eh-attest inspect`: passed.
- `python -m unittest discover -s tests -v`: 36 passed.
- Tracked-artifact and public-reader-path audits: passed.
- Prospective clean checkout: `npm ci`, Python virtual-environment install, all builds, all tests, demo, and certificate verification passed.

## Known failures

- None.

## Security limitations

- Executor Attestation still requires provider-specific trust dispatch hardening.
- Nonce context binding and concurrent one-use verification are not yet implemented.
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
- `STATUS.md`

## Commands to reproduce

```powershell
npm ci
npm run build
npm test
python scripts/verify_certificate.py examples/reference-run/containment-certificate.json
```

## Next engineering milestone

Replace mythological labels in all public documentation, diagrams, command output, and tests with functional component names.

## Exact next command

```powershell
rg -n "Neural Link Zero|Cerberus|Aegis|Talos|Nemesis|Delta|Assurance|Iaso" README.md docs examples tests
```
