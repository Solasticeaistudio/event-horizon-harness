# Protected signing and evidence boundaries

Event Horizon treats capability signing, evidence receipt signing, and containment-certificate signing as protected service operations. The portable harness now enforces a cryptographic request boundary around every mutation endpoint and keeps service signing seeds out of ordinary JSON configuration. This is a concrete interface and local regression target; it is not a claim that the development machine is separately administered.

## Protected operations

| Service | Authenticated mutations | Public read-only operations |
|---|---|---|
| Capability signer | `issue`, `consume` | `info` |
| Evidence recorder | `append` | `info`, `verify` |
| Certificate signer | `build` | `info`, `verify` |

Each protected request carries an Ed25519 authorization envelope binding the protocol schema, service audience, authorized-client key ID, random 256-bit nonce, integer issuance and expiration times, and canonical digest of the complete unsigned RPC envelope. The signed digest therefore covers the message type, request ID, deadline, and exact body. Unknown fields, noncanonical signatures, wrong audiences or keys, request mutation, future or expired authorizations, and unsupported algorithms fail closed.

The authorization nonce is consumed only after signature, freshness, audience, and request-digest validation. SQLite stores the nonce, request digest, expiry, and consumption time under `(namespace, audience, nonce)`. Insert-once consumption is durable across service restart and atomic across cooperating local processes. A committed test races 16 verifier processes and requires exactly one success.

## Key handling

Capability, recorder, and certificate Ed25519 seeds are no longer serialized into service JSON. The development harness provisions separate 32-byte raw seed files with exclusive creation and, on POSIX, mode `0600` inside mode `0700` directories. Services reject symlinks, non-regular files, wrong lengths, overly broad POSIX permissions, and files replaced between inspection and descriptor open. They load the seed through a file descriptor; the derived private-key object is not copied into coordinator or executor configuration. The seed remains in its restricted file so signer identities survive ordinary service restart.

The executor configuration contains only the capability verification key and key ID. It receives no signing-key path, protected-client private key, authoritative replay path, recorder key, or certificate key.

## Exact claim boundary

The default harness still runs every process under one host account. The harness itself generates the development signing seeds and authorized-client keys. Stdio pipes are authenticated at the message layer but are not an independently administered network service, mTLS channel, HSM, KMS, or hardware security boundary. Windows ACL strength is not verified by the portable key helper. A same-user or host-administrator compromise can read process memory or protected files and remains inside the trusted computing base.

Request authentication proves which configured client submitted bytes; it does not prove those bytes describe reality. In the development topology the coordinator is the authorized client for signer, recorder, and certificate mutations. A compromised authorized coordinator can submit false evidence or validly request operations that pass the protected service's own checks. The evidence chain detects later mutation, loss, reordering, and linkage failure; it does not make a dishonest authorized source truthful.

A separately administered deployment must provision keys outside the harness, run services under distinct principals or hosts, make private-key and evidence storage inaccessible to the execution cell and coordinator where appropriate, authenticate transport peers, split recorder source identities, protect client credentials, use rollback-resistant storage, publish pinned verification keys, define rotation and revocation, and monitor authorization failures. A multi-host deployment also requires a linearizable replay backend; local SQLite is not sufficient.
