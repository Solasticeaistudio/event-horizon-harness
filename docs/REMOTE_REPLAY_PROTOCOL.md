# Authenticated remote replay protocol

Event Horizon defines a cross-language protocol for moving replay-sensitive transitions behind one authoritative service. The Python reference service and clients implement capability redemption and protected-request authorization. Executor Attestation implements the same client contract for nonce creation, inspection, and atomic consumption.

The protocol is a linearizable state-machine interface: a conforming backend must assign every completed transition one position in a single total order. The included reference implementation achieves that order with `BEGIN IMMEDIATE` against one SQLite database. It is a conformance implementation, not a multi-node consensus system. A deployment that needs several active hosts must supply a linearizable database or replicated state machine and must fence old leaders.

## Authenticated envelope

Every request is strict canonical JSON with exactly these fields:

```text
schema, algorithm, service_id, client_key_id, request_id,
issued_at, expires_at, expected_epoch,
minimum_checkpoint, minimum_checkpoint_digest,
operation, partition, payload, signature
```

`algorithm` is fixed to `Ed25519`. The signature covers every other field. The service checks the key ID against a configured client policy, verifies the signature and freshness window, and authorizes the exact operation/partition pair. Unknown clients, algorithms, fields, operations, partitions, expired requests, future requests, malformed canonical values, and invalid signatures fail closed.

Every successful protocol exchange returns strict canonical JSON with exactly:

```text
schema, algorithm, service_id, server_key_id, epoch,
checkpoint, checkpoint_digest, request_id, request_digest,
accepted, status, result, responded_at, signature
```

The server signature binds the exact complete request digest and request ID to the decision, result, service identity, epoch, and checkpoint. Clients pin the server public key and reject response swapping, key substitution, algorithm substitution, malformed results, and unsigned errors. Transport security is still required in deployment for confidentiality, traffic-analysis resistance, and network-level policy; message signatures do not provide those properties.

## Operations

The protocol currently admits five operations:

| Operation | Atomic state rule |
|---|---|
| `nonce-create` | Insert one complete issued nonce record if absent. |
| `nonce-consume` | Compare context and expiry, then transition `issued -> consumed` once. |
| `nonce-inspect` | Return the signed record and transition an elapsed issued record to `expired`. |
| `capability-consume` | Insert one capability ID and exact signed-claims digest once. |
| `authorization-consume` | Insert one authorization nonce and exact protected-request digest once. |

A repeated token with the same binding returns replay. Reuse with a different digest or lifetime returns `collision` and the adapters raise a state-integrity error. The service never implements consumption as a read followed by a later delete.

## Checkpoints and rollback detection

Checkpoint zero is a deterministic digest of the service ID and current epoch. A client constructed or explicitly promoted at checkpoint zero may omit the digest, in which case it computes that epoch's genesis digest; an explicitly supplied value must equal the same digest. A restored checkpoint greater than zero always requires its exact digest and never defaults to genesis. The TypeScript client rejects negative, non-integer, malformed, and values outside JavaScript's safe integer range before any request is sent. Every authenticated transition, including an ordinary replay denial, advances a strictly monotonic checkpoint and hash-chains:

- the previous checkpoint digest;
- epoch and checkpoint number;
- exact signed request digest;
- accepted bit and status; and
- canonical result digest.

The client sends its last observed checkpoint and digest with every request. The service accepts a transition only if that checkpoint exists in its retained history with the same digest. The client serializes its own calls and rejects a response below its last checkpoint or a different digest at the same checkpoint.

This detects restoration to a checkpoint older than one already retained by that client. It does not make the SQLite file tamper-proof, prevent rollback before any client has retained a newer checkpoint, or provide an external transparency log. Production clients must persist their checkpoint on rollback-resistant storage or publish signed checkpoints to an independently administered monitor. The reference implementation retains checkpoint history without compaction.

## Epoch and failover semantics

Epoch changes are never learned implicitly from a network response. Promotion is an explicit trusted operator action:

1. fence the previous writer;
2. restore a replica whose checkpoint and digest equal the selected continuity point;
3. atomically increase the service epoch;
4. distribute the new epoch, checkpoint, digest, and optionally rotated server key over a trusted configuration channel; and
5. have clients explicitly adopt that state before sending another transition.

Clients reject lower, equal, unexpected, or network-proposed epochs. They also reject promotion to a lower checkpoint or a different digest at a nonzero checkpoint they already know. Promotion at checkpoint zero is permitted only for an empty history and rebinds checkpoint zero to the deterministic genesis digest of the new epoch. A new client joining after a nonempty promotion must be provisioned with the promoted service's explicit current continuity checkpoint and digest; it cannot silently default a restored state to genesis.

The reference `promote()` method validates restored local continuity and increments the epoch. The TypeScript `adoptEpoch()` API is asynchronous and must be awaited. Adoption is enqueued behind all earlier remote operations, and later operations wait for it, so an in-flight response is always verified against the key, epoch, transport, and checkpoint state under which its request was sent. Adoption validates the complete replacement state before mutating the client, and a rejected operation does not poison the serialization queue. The synchronous Python client provides the corresponding exclusion with its existing reentrant lock.

Promotion does not fence an old host. Tests prove that promoted clients reject the old primary; they do not claim that an unfenced old primary cannot serve obsolete clients. Safe automatic failover requires an external consensus/fencing mechanism.

## Failure and availability semantics

Timeout, connection failure, non-200 response, oversized body, noncanonical JSON, bad signature, unexpected key, unexpected epoch, checkpoint regression, malformed result, database error, or client-policy denial cannot produce an accepted local transition. The caller receives an exception and must deny authorization. The client does not fail over automatically because silently selecting a replica could select stale state.

The TypeScript HTTP transport limits responses to 65,536 raw bytes. It rejects an oversized valid `Content-Length` before reading, also counts bytes while streaming because the header is not trusted, uses a streaming UTF-8 decoder across chunk boundaries, cancels the reader as soon as the bound is crossed, and parses JSON only after the complete bounded response arrives. It never falls back to an unbounded `response.text()` call when a body stream is unavailable.

An ambiguous transport failure may occur after the service committed but before the client received its signed response. Retrying the same security token is safe: the service returns replay rather than a second success. The original operation is treated as burned unless the caller obtains a valid response; availability is sacrificed rather than reconstructing authority.

## Conformance evidence

`tests/test_remote_replay.py` covers exact one-use behavior, 48-way concurrency, collisions, nonce context, request forgery, unknown fields, response forgery, response swapping, rollback, epoch promotion, checkpoint restoration, stale-primary rejection, unsafe promotion, outages, and the HTTP binding. `attestation/tests/remote-nonce-persistence.test.mjs` covers the awaitable Executor Attestation adapter, response forgery, stale epochs, and outages. `attestation/tests/remote-replay-client-state.test.mjs` covers serialized adoption, queue recovery, atomic validation, and checkpoint-state invariants. `attestation/tests/remote-http-transport.test.mjs` covers bounded streaming, declared and chunked oversize responses, split UTF-8, and reader cancellation. `scripts/verify_remote_replay_interop.py` runs a real Node client against the Python HTTP service and verifies both languages agree on canonical bytes, Ed25519 key IDs and signatures, response bindings, nonce records, and checkpoints.

The portable demo continues to use local SQLite. Deploying the remote interface under separate principals, protected keys, TLS, rollback-resistant client checkpoint storage, monitoring, backups, and a genuinely linearizable multi-host backend remains future infrastructure work.
