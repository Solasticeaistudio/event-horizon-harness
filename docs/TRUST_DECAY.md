# Monotonic trust and authority decay

Capabilities bind a decay profile ID/version, complete profile digest, initial-authority digest, refresh-requirement digest, issuance/expiry, and one-use invocation limit. The verifier reconstructs the profile from the signed compiled ceiling and rejects any mismatch before redemption.

At redemption, the decay engine computes current authority before permitting an effect. It can independently reduce lifetime, calls, read/write bytes, destinations, tools, actions, resources, integer argument ranges, parallelism, and effect severity. Triggers include elapsed time, use/data counters, denials, risk, canary events, trust/policy age, environment changes, and workload restarts.

Each transition must satisfy:

```text
Authority(t + 1) subset-of Authority(t)
```

Counters and maximum observed time are monotonic. Clock rollback uses the maximum previously observed time. Profile replacement, counter reset, expiration extension, state corruption, and storage unavailability fail closed. In-memory state is used for local unit tests; the process-separated signer and executor use SQLite transactions for restart continuity on one host.

Refresh creates a different capability identity and requires fresh attestation and authorization digests. It is a new authorization event, not an extension of an existing capability. A trust upgrade cannot enlarge an already issued capability, and a consumed capability is not revived.

The reference profile is deliberately narrow and still operates alongside the independent one-use capability store. SQLite does not claim distributed atomicity, consensus, rollback-resistant storage, or transactional atomicity with an external side effect.
