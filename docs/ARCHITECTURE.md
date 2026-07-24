# Architecture and trusted computing base

## Process topology

```text
hostile request
      |
      v
Intent Canonicalizer ----> Executor Attestation verifier
      |                              |
      +--------> guardian quorum <---+
                         |
                         v
              Evidence Signing / broker
                         |
                 exact capability
                         v
                sacrificial executor

Every transition ----> independent logical evidence recorder
                                      |
                                      v
                         Evidence Chain Verification
```

Each named box is a separate OS process in `ProcessSeparatedHarness`. Processes communicate over stdin/stdout pipes using the same minimal protocol: four-byte big-endian length followed by canonical UTF-8 JSON. The protocol rejects duplicate keys, noncanonical encodings, unknown message types or fields, excessive bytes, strings, collections or nesting, expired deadlines, and excess requests.

## Authority flow

1. The Intent Canonicalizer parses and canonicalizes a typed request. It has no tool registry, signing key, network client, or execution authority.
2. Executor Attestation verifies a verifier-issued one-time nonce, registered device/AK identity, signed measurement evidence, freshness, PCR selection, and policy. It returns evidence, never authorization.
3. The Static Policy Guardian, Executor Attestation Guardian, Lineage Budget Guardian, and Behavioral Transition Guardian each evaluate the same request. One permissive guardian cannot override another veto or widen static policy.
4. The broker asks the isolated signer to mint a short-lived capability for the exact canonical request digest.
5. The executor accepts only the public verification key and rechecks every binding before one pre-registered operation. Redemption state outside the executor prevents replay after executor compromise.
6. The independent logical evidence recorder returns a signed receipt for every fixed-size event envelope. Evidence Chain Verification signs a certificate only after recorder verification and verified teardown.

## Capability bindings

The capability commits to request ID and digest, session and agent, operation/resource/arguments, executor and device ID, image/measurement digest, Executor Attestation bundle and result digests, verifier-policy digest, static-policy digest, signer key ID, expiry, one-use invocation count, and maximum output bytes.

## Trusted computing base inventory

| Component | Trusted for | Explicitly lacks |
|---|---|---|
| Protocol codec/schema | Canonical parsing and bounds | Policy, keys, execution |
| Executor Attestation verifier | Identity and measurement decision | Authorization and capability key |
| Static Policy Guardian and quorum coordinator | Subtractive policy and veto combination | Execution and signing key |
| Signer/broker | Exact capability minting and redemption state | Workload code and arbitrary connectors |
| Executor verifier/dispatcher | Binding checks and fixed operations | Capability private key and ambient credentials |
| Independent logical evidence recorder | Ordered authoritative evidence and receipts | Workload execution authority |
| Evidence Chain Verification | Final evidence-domain validation and signature | Capability minting and workload access |
| Firecracker, host kernel, KVM, guest image, watchdog | Hardware cell isolation and teardown in KVM mode | External service credentials |
| TPM, AK, `tpm2-tools`, Executor Attestation parser | Hardware identity/measurement evidence in TPM mode | Action authorization |

The model, hostile executor contents, synthetic services, local audit decoy, model-based guardian, and human-facing output are untrusted. Development deployments currently run the seven trusted processes on one host; distinct processes reduce key exposure and confused-deputy paths but do not make a compromised host kernel trustworthy.

## Firecracker cell

The Linux/KVM target has a read-only minimal rootfs, a per-run scratch image, no package manager, no host mounts, no NIC, no MMDS/metadata endpoint, and one fixed vsock protocol. An external watchdog terminates the VM and invalidates then deletes scratch/configuration. If KVM or required artifacts are missing, the default behavior is denial. The explicit process fallback writes `hardware_isolation_claimed: false`.

## Evidence and certificate

Events carry global and per-source sequence numbers and a previous-hash link. Recorder receipts are Ed25519 signed. Startup validates the persisted chain before accepting another event; loss, reordering, mutation, and source gaps deny further recording. The certificate contains or hashes all seven required evidence domains and can be verified with only its public key.
