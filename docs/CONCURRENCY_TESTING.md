# Concurrent redemption testing

`ConcurrentRedemptionHarness` releases hundreds of thread attempts simultaneously against multiple verifier instances sharing a durable SQLite consumption domain. Attempts use distinct test idempotency keys and deterministic storage/executor/recorder delays, partitions, retry pressure, and response-loss classification. A restart test creates new verifier/store instances over the same database.

The trusted result counter is outside the attempted workload. Passing requires no more than one committed effect. A response lost after commit is indeterminate rather than a denial, and retry cannot create a second effect. Different idempotency keys, replica selection, or restart do not change the signed capability identity.

A deliberately non-atomic store is available only when `EH_ENABLE_VULNERABLE_CONTROL=1`. It emits a loud runtime warning, and the same harness must detect multiple commits. The flag is set only inside the positive-control test and is never enabled by default.

Run `make test-concurrency`. SQLite establishes single-host transactional behavior only; it is not a distributed commit protocol and cannot atomically commit an arbitrary external effect with capability consumption.
