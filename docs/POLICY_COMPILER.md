# Deterministic policy compiler

`TrustedPolicyCompiler` is the authorization boundary between an adaptive proposal and capability issuance. It does not call an LLM. Identical validated inputs, guardian reductions, approvals, and explicit compiler time produce identical output.

The compiler validates exact schemas and then computes a subtract-only intersection across:

```text
effective authority =
    static global maximum
    intersection candidate task ceiling
    intersection exact requested authority
    intersection provider-derived trust
    intersection tenant/environment policy
    intersection mandatory approvals
    intersection guardian reductions
```

It rejects unknown tools, actions, resources, destinations, data classes, undeclared action/resource relations, forbidden argument keys, stale task fingerprints, stale policy versions, expired trust, insufficient provider trust, unsatisfied approval gates, shadow output, and empty or expired authority.

The compiled result binds:

- task ID and fingerprint;
- subject and workload identity;
- tenant and environment;
- synthesizer and compiler versions;
- global policy version;
- candidate digest;
- provider attestation result, bundle, method, key, and effective trust;
- exact tool/action/resource and argument-key limits;
- network/data scopes and byte/call/parallelism/duration budgets;
- required attestations and approvals;
- guardian reductions;
- decay profile and expiration.

The compiler output carries an internal SHA-256 integrity digest. The capability signs the complete compiled structure and its digest. Redemption reconstructs the strict compiled schema, verifies its digest, confirms that it permits the exact canonical request, and compares current provider evidence and independently configured policy, verifier-policy, tenant, environment, and audience values.

Provider trust is authoritative. Requested trust is advisory. Simulator evidence maps only to `simulated`; a simulator result claiming `hardware` is contradictory and fails closed. An existing capability cannot gain authority from a later trust upgrade, while a trust downgrade below its signed constraint denies redemption.

Current limitations remain: the development provider result is rooted in the separately executed TypeScript verifier, the default environment is a same-host research topology, and TPM verification is not production complete. See [ATTESTATION_THREAT_MODEL.md](ATTESTATION_THREAT_MODEL.md) and [../KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md).
