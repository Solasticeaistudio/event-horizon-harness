# Narrow TLA+ model

`formal/EventHorizon.tla` models policy proposal/compilation, provider attestation, issuance, guardian and behavioral reduction, decay, task/workload binding, one-use redemption, effect commit, expiry/revocation, canary attempts, crash/recovery, ambiguity, and denial-certificate state. The configuration checks the 20 invariants listed in `docs/SECURITY_INVARIANTS.md` and the phase requirements.

`EventHorizonBroken.tla` deliberately replaces intersection with additive guardian authority. TLC is expected to find `GuardianNeverAddsAuthority` violated.

Run:

```bash
make test-formal
python scripts/check_formal_model.py --require-tlc
```

The default command performs a structural check and runs TLC only when Java and `TLA2TOOLS_JAR` are available. This workstation had neither Java nor TLC, so no TLC state-space result is claimed. Extended CI should pin a reviewed `tla2tools.jar`, set `TLA2TOOLS_JAR`, and use `--require-tlc`.

Even a successful TLC result checks only the modeled transition system, finite configured authority set, and stated assumptions. It does not prove that the Python/TypeScript implementation, OS, SQLite, cryptography libraries, hardware, or deployment matches the model.
