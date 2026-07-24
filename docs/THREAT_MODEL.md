# Threat model

## Adversary

Assume an autonomous frontier agent can:

- reason over long horizons and coordinate child agents;
- inspect all inputs, outputs, local source, binaries, logs, and configuration;
- write and execute arbitrary code inside the assigned workload;
- obtain root in the guest through an injected compromise;
- exploit unknown bugs in custom middleware, parsers, kernels, or hypervisors;
- steal every secret available to a compromised process or host;
- manipulate humans and probabilistic guardians through generated output;
- exploit timing, size, error, and formatting channels;
- understand the containment architecture and intentionally search for authority.

## Protected assets

- external network access;
- real cloud, cluster, source-control, database, and signing identities;
- capability-minting authority;
- control-plane configuration;
- neighboring workloads and later sessions;
- persistent state;
- authoritative evidence and teardown proof.

## Trusted computing base for v0.2

- request schema and canonical serializer;
- static policy evaluator;
- guardian quorum coordinator;
- capability mint/verifier;
- external recorder and certificate signer;
- pre-registered executor dispatcher.

The model, agent harness, execution cell, synthetic services, model-based guardian, and human-facing output are untrusted.

## Non-goals in v0.2

- proving resistance to real hypervisor or firmware zero-days;
- eliminating electromagnetic, acoustic, thermal, or power side channels;
- securely exposing arbitrary HTTP, shell, package installation, or dynamic tools;
- asserting that HMAC keys on one development machine equal hardware-backed attestation;
- claiming absolute or mathematical inescapability.

## Security claim

Under the stated topology and assumptions, compromise of the hostile workload does not provide a transferable credential or a causal path to external authority. Each assumption will be converted into an injected-compromise test.
