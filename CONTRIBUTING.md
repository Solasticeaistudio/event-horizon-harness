# Contributing

Contributions should preserve the core invariant: guardians may only subtract authority, and no dynamic approval may exceed the deterministic static-policy ceiling.

## Development workflow

1. Create a focused branch from current `main`.
2. Install from the committed lockfile with `npm ci` and `python -m pip install -e .`.
3. Add tests that fail before the change and pass after it.
4. Run `npm run build`, `npm test`, and `python scripts/verify_capability_vectors.py`.
5. Update documentation, `KNOWN_LIMITATIONS.md`, and `STATUS.md` when behavior or claims change.
6. Submit a pull request describing the security invariant, trust-boundary impact, tests, and remaining limitations.

Keep dependencies pinned and explain new trusted-computing-base dependencies. Reject unknown fields and ambiguous security inputs rather than adding permissive compatibility paths. Do not commit dependency trees, build output, credentials, private keys, `.env` files, archives, real target data, or AI-development transcripts.

Security-sensitive changes should include negative and concurrency tests. Changes to canonicalization, capability claims, attestation trust derivation, nonce state, guardian combination, evidence, or teardown require an explicit attack analysis.

## Safety scope

Only harmless synthetic adversaries and owned range fixtures belong in this repository. Do not contribute credential theft, ransomware, denial-of-service, evasion, exploit compilation, public-target connectors, or autonomous offensive modules. Report suspected containment bypasses through `SECURITY.md`, not a public pull request.
