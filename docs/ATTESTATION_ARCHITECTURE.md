# Executor Attestation Architecture

Executor Attestation supplies identity and measurement evidence to the Event Horizon guardian quorum. It does not authorize operations. The deterministic static policy remains the maximum authority that the capability broker can issue.

## Trust boundary

The executor and every bundle field are untrusted. Verification runs outside the sacrificial executor. A verifier must select an implementation from its configured method registry, pass the complete signed bundle and challenge context to that implementation, and use only the verifier implementation's result to assign a trust level.

```text
Sacrificial executor
    |
    | signed bundle + nonce context
    v
Executor Attestation verifier
    |
    +--> simulator verifier -> development trust only
    +--> TPM verifier       -> hardware trust only after full quote validation
    |
    v
Attestation Guardian (veto only)
    |
    v
Static-policy intersection -> capability broker
```

## Packages

- `@event-horizon/attestation-crypto` implements canonical bytes, digests, signatures, and key identifiers.
- `@event-horizon/attestation-core` owns schemas, nonce state, verifier dispatch, freshness, replay checks, and measurement policy.
- `@event-horizon/attestation-simulator` produces development-only evidence.
- `@event-horizon/attestation-tpm` integrates with TPM 2.0 tooling and quote evidence.
- `@event-horizon/attestation-sdk` exposes the local client and server API.
- `@event-horizon/attestation-middleware` adapts verification to HTTP-like request objects.

The `eh-attest` CLI supports explicit development workflows. The remote service workspace is private and remains unimplemented for production use.

## Authority relationship

Successful attestation is necessary where policy requires it, but never sufficient. The broker binds the verified bundle digest, verification-result digest, verifier-policy digest, device identity, executor measurement, executor identity, session identity, exact operation, exact arguments, static-policy digest, expiration, and one-use identifier into the signed capability.
