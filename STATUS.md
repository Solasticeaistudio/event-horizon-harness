# Status

## Completed

- Repository inventory completed; the initial worktree was clean.
- Renamed the subsystem, source tree, packages, public TypeScript APIs, Python provider, CLI, environment variables, integration tests, evidence fields, and active documentation to Executor Attestation.
- Added architecture, threat-model, verification, and concise renaming documents.
- Removed tracked generated JavaScript build products and the tracked dependency tree encountered during the namespace migration.
- Regenerated the attestation lockfile with only current workspace paths.

## Tests executed

- `npm run build` in `attestation/`: passed for all 8 workspaces.
- `npm test` in `attestation/`: 16 passed, 1 skipped (opt-in real TPM).
- `eh-attest prove`, `eh-attest verify`, `eh-attest inspect`: passed.
- `python -m unittest discover -s tests -v`: 36 passed.

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
- `STATUS.md`

## Commands to reproduce

```powershell
Set-Location attestation
npm install
npm run build
npm test
Set-Location ..
python -m unittest discover -s tests -v
```

## Next engineering milestone

Remove remaining generated artifacts, release archives, stale inventories, and internal AI-development material from the public reader path.

## Exact next command

```powershell
git ls-files | Select-String -Pattern 'node_modules|__pycache__|\.pyc$|dist/|build/|\.zip$'
```
