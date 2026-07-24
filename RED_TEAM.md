# Public red-team guide

Use owned synthetic environments only and follow `SECURITY.md`. The useful outcome is a minimal, reproducible counterexample to a documented invariant, not damage or access to a real system.

## Challenge goals

Demonstrate one of the following within the shipped synthetic harness:

- execute outside signed authority;
- replay a consumed capability;
- widen operation arguments after approval;
- transfer a capability across executors;
- reuse an Executor Attestation nonce;
- forge hardware trust from simulator or malformed TPM evidence;
- alter the authoritative evidence chain undetected;
- survive verified teardown with usable authority or declared persistence.

An availability-only failure is not a containment bypass. A result must cross an authority, integrity, replay, transfer, evidence, or teardown boundary while the corresponding verifier reports success.

## Safe submission evidence

Provide:

1. the exact Git commit and platform versions;
2. a minimal synthetic manifest and deterministic seed;
3. the exact command sequence from a clean checkout;
4. the canonical request, relevant capability or attestation digest, and expected policy digest;
5. sanitized recorder events and certificate, including the verification output;
6. a concise explanation of the violated invariant and why the result is not an already documented limitation.

Do not submit secrets, real credentials, public target identifiers, weaponized payloads, exploit binaries, destructive code, or unrelated data. Report plausible bypasses privately before publishing details.
