# Architecture — v0.3

```text
Model / agent loop (untrusted)
            |
            | typed proposed intent
            v
Neural Link Zero (canonicalization only)
            |
            v
Independent guardian quorum
  Cerberus  — static policy veto
  HardProof — nonce-bound identity and executor measurement veto
  Aegis     — lineage-wide budget veto
  Talos     — suspicious-transition veto
            |
            | exact, one-use capability
            v
Sacrificial executor
  pre-registered operation implementations only
            |
            | fixed result envelope
            v
Sanitized result channel

One-way side plane:
  every request, decision, capability, denial, and result
            -> external hash-chained recorder
            -> Containment Certificate
```

## Why this is not the original Neural Link

The original Neural Link correctly centralized action mediation, capability checks, rate limits, circuit breakers, simulation, and observability. It also supported dynamic real-tool registration, callable handlers, live/simulation mode switching, and direct execution. Those are useful platform features but too much authority for a frontier containment TCB.

Neural Link Zero therefore:

- has no tool registry;
- has no callable handlers;
- cannot switch into a live mode;
- contains no network client;
- contains no secrets;
- cannot mint authority by itself;
- cannot execute the requested operation.

## Physical target topology

The production Black Hole tier becomes:

```text
Hostile route-less bare-metal island
  -> fixed protocol / data diode
  -> quarantine receiver
  -> separately administered guardian and signing appliance
  -> separately administered evidence store
```

The sacrificial host is not a Kubernetes worker, has no cloud role, no BMC path reachable from the workload side, no adjacent tenants, and no management route during execution.


## v0.3 implemented development path

The HardProof simulator now produces a nonce-bound Ed25519 proof. A separately invoked verifier checks device registration, signature, freshness, replay state, and measurement policy. The resulting bundle digest is recorded and included in Event Horizon capability claims. This is a development separation boundary, not yet a hardware or process-isolation claim.
