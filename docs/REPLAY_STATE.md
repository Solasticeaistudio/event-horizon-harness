# Durable replay state

Event Horizon uses SQLite-backed replay state in the default local and process-separated harnesses. This makes attestation nonces and capability redemptions atomic across cooperating processes on one host and durable across their restarts. It is a deliberately bounded local implementation, not a distributed lock or consensus system.

## Attestation nonce transitions

`SqliteNoncePersistence` stores each 32-byte canonical nonce under `(namespace, nonce)` with its complete context, canonical context digest, issuance and expiration times, state, and consumption time. The accepted state transitions are:

```text
issued --conditional UPDATE--> consumed
issued --expiration---------> expired
```

Consumption succeeds only when the nonce is still `issued`, its context digest matches, and its exclusive expiration is in the future. The comparison and state change occur in one SQLite statement. Unknown, expired, consumed, wrong-context, malformed, unavailable, corrupt, or schema-incompatible state fails closed.

## Capability consumption

`SqliteCapabilityConsumptionStore` records `(namespace, domain, capability_id)` plus the digest of the complete signed claims, expiration, and consumption time. A transaction beginning with `BEGIN IMMEDIATE` performs an insert-once transition. The first valid redemption commits; later redemptions return replay. Reuse of one capability ID with different signed claims is treated as a state-integrity failure.

The authority-side broker and the executor are separate consumption domains. This is intentional: the broker burns the externally presented capability before dispatch, while the executor independently burns the same capability before the operation. Every replica serving one domain must use the same database, namespace, and domain.

## Protected request authorization

Signer, recorder, and certificate mutation requests carry separate signed authorization nonces. `SqliteAuthorizationReplayStore` records `(namespace, audience, nonce)`, the canonical complete-request digest, expiration, and consumption time. Signature, audience, freshness, and request binding are checked before one insert-once transaction burns the nonce. The authority signer uses the authority database; recorder and certificate audiences use a separate logical evidence database.

## Deployment boundary

The process harness keeps authoritative nonce and broker state in `trusted-control/replay-state.sqlite3`. The executor configuration receives neither that path nor the authority database; it uses a separate defense-in-depth database under `executor-state/`. Exposing the authoritative database to the execution cell would collapse the replay guarantee.

This is configuration separation in the portable process fallback, not an enforced filesystem security boundary. The processes run under the same host account, so arbitrary same-user host access could discover or modify both paths. A production microVM or jail must make the authoritative database unreachable from the hostile cell. The SQLite implementation demonstrates durable replay semantics; it does not repair the documented absence of production cell isolation.

Both implementations enable SQLite write-ahead logging, full synchronous durability, a bounded busy timeout, and an explicit schema-version row. Initialization or transactions fail closed on database errors. The committed tests race 24 separate Node verifier processes for one nonce and 16 spawned Python broker processes for one capability; each test requires exactly one success. Restart tests confirm consumed state survives verifier, signer, and executor process replacement.

The guarantee is limited to cooperating processes using one SQLite database on a local filesystem. It does not cover multiple hosts, network filesystems, Byzantine database clients, or a compromised host administrator. The database file, WAL, directory permissions, namespace/domain configuration, storage durability, backups, and rollback protection are trusted computing base concerns. Deleting or restoring an old database can erase consumption history. Records are retained without compaction in this release.

A future multi-host backend must provide a linearizable insert-once or compare-and-transition operation, authenticated clients, durable storage, namespace isolation, schema/version control, backup and rollback defenses, and failure-mode tests. It must not implement replay defense as a separate read followed by delete.
