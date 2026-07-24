# Event Horizon integration

## Trust flow

```text
sacrificial executor
  -> Executor Attestation prover creates nonce-bound proof
  -> independent Executor Attestation verifier checks device key, freshness, signature and measurements
  -> verification result becomes a Executor Attestation guardian input
  -> Event Horizon guardian quorum may veto
  -> capability broker issues exact one-use authority only after every veto layer accepts
```

## Required binding

The verified result supplied to Event Horizon must include:

- device ID;
- proof method;
- trust level;
- key ID;
- measurement map;
- proof bundle digest;
- verifier policy digest;
- verification timestamp.

The Event Horizon capability should bind to the digest of this result, not merely a free-form executor name.

## Non-responsibilities

Executor Attestation must never:

- approve an operation;
- expand an action request;
- select a tool;
- mint Event Horizon capability tokens;
- hold model prompts or agent memory;
- share a private signing key with the hostile executor.
