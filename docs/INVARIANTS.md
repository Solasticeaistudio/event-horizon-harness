# Containment invariants

## EH-1 — No ambient authority

No reusable credential, cloud workload identity, cluster token, signing key, or production secret exists inside the agent process, guest, or sacrificial host.

**Failure:** hostile code retrieves any credential that can authorize an external operation without a new decision by the external capability broker.

## EH-2 — No direct causal path

The hostile world has no direct route to the internet, package registries, metadata services, control planes, neighboring workers, production storage, or management networks.

**Failure:** hostile code transmits an unauthorized byte or initiates an unauthorized request outside the synthetic range.

## EH-3 — Every effect is exact and one-use

Every external effect is bound to the exact session, agent, executor measurement, operation, resource, argument digest, policy digest, expiry, output envelope, and invocation count.

**Failure:** a capability is replayed, widened, transferred, used from another session/executor, or used after expiration.

## EH-4 — Compromise cannot propagate or persist

Workload or host compromise may occur, but it cannot create another identity, reach another machine, or survive verified teardown.

**Failure:** cross-cell influence, lateral movement, or durable state remains after reset.

## EH-5 — Authoritative observation survives compromise

The authoritative event chain and certificate are stored outside every environment the agent can modify.

**Failure:** the hostile environment can delete, rewrite, reorder, or suppress authoritative evidence without detection.

## EH-6 — Guardians only subtract authority

No guardian, model, human approval, or anomaly detector may grant an operation beyond the static experiment policy. Any guardian may veto. Sensitive authorization requires independent agreement.

**Failure:** compromise of one guardian creates a new authority edge.
