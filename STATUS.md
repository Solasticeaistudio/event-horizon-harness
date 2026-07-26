# Status

## Completed

- Audited the repository and recorded verified trust, capability, replay, evidence, and isolation paths in `docs/BASELINE_AUDIT.md`.
- Implemented typed adaptive task-policy proposals, deterministic trusted compilation, static/rule/model/shadow/evaluation modes, conservative fallback, and sizing metrics.
- Enforced provider-derived trust, exact capability bindings, durable one-use redemption, canary tripwires, signed denial certificates, behavioral subtract-only reduction, and monotonic authority decay.
- Added Hypothesis/stateful protocol tests, concurrent redemption stress with a vulnerable positive control, deterministic chaos hooks, bounded adaptive-adversary integration, literature metadata feed, hardware-failsafe simulator, and a narrow TLA+ model.
- Added security reporting, public claim-boundary documentation, and reproducible extended-suite commands.

## Tests executed

- `python -m unittest discover -s tests -v`: 179 tests passed before the final adaptive/hardware additions; targeted additions passed (adaptive 4, positive controls 2, literature 4, hardware 10, formal structure 1).
- `python -m ruff check src tests scripts`: passed.
- `python scripts/lint_python.py`: passed.
- `python scripts/check_repository_policy.py`: passed.
- `python scripts/check_literature_feed.py --live`: passed with no source drift; six metadata campaigns remain pending human review.
- `python scripts/check_formal_model.py`: structural checks passed; TLC skipped because Java and a pinned TLA jar are unavailable on this host.
- TypeScript `npm ci`, build, typecheck, tests, and remote replay interoperability passed in the preceding release verification.

## Known failures

- No portable test failure is known. Full post-addition `make security-report` and clean-install verification remain to be run after documentation/CI edits.
- Physical hardware-in-the-loop, production TPM, Firecracker, and TLC execution are unavailable in this environment.

## Security limitations

- Adaptive and behavioral model outputs are untrusted proposals; only deterministic compilation and reductions enforce authority.
- The local replay/evidence stores and development keys remain under one host account; no consensus-backed multi-host or physically independent recorder is claimed.
- Decay and external-effect reconciliation are fail-closed but not a distributed transaction across every possible effect system.
- Canary denial-certificate emission is available through the certificate infrastructure but is not automatically wired into every canary event path.
- The adaptive LLM endpoint is optional, bounded, and controller-side; no paid endpoint or model success claim is required.
- The hardware subsystem is a simulator only; no firmware target or physical switch was tested.
- The formal model is a narrow state-machine model and has not been TLC-checked on this host.
- Tests are project-authored and no external security audit has occurred. No frontier-model containment claim is made.

## Files changed

- Adaptive policy, compiler, broker trust/decay, canary, denial-certificate, behavioral, concurrency, chaos, adversary, literature, hardware, and formal modules under `src/event_horizon/` and `formal/`.
- New tests under `tests/`, reporting/evaluation scripts under `scripts/`, Make targets, CI-facing documentation, README, and public claim-boundary/report documents.

## Commands to reproduce

```powershell
npm ci
npm run build
npm run typecheck
npm test
python -m pip install -e ".[test]"
python -m unittest discover -s tests -v
python scripts/verify_remote_replay_interop.py
python scripts/generate_security_report.py
```

## Next engineering milestone

Run the complete clean-install/security-report workflow, then deploy the authenticated replay and evidence interfaces under separate principals with rollback-resistant replicated storage and independent review.

## Exact next command

```powershell
python scripts/generate_security_report.py
```
