# Baseline-versus-contained experiment format

The versioned format in `schemas/experiment.schema.json` pairs a `baseline` record with an `event-horizon` record. Both records must bind the same range image, scripted attacker configuration, static policy, executor measurement, and seed. The validator rejects unknown fields, malformed digests, ambiguous numeric types, reversed timestamps, inconsistent paired inputs, baseline attestation claims, and contained records without an attestation digest.

Each record includes the experiment ID, mode, range and configuration digests, policy and executor measurements, attestation digest, seed, time interval, highest synthetic privilege stage, credential outcomes, replay and transfer attempts, lateral reach, unauthorized egress bytes, teardown persistence, evidence tampering, evidence-chain verification, and optional Ed25519 certificate signature metadata.

`null` and `not-measured` are intentional outcomes. They prevent an interface-only run from being mistaken for a teardown test, authoritative evidence-chain verification, or a signed containment certificate. A signature value records certificate metadata; this experiment parser does not itself verify that signature. Certificate verification remains an independent step.

The committed `examples/experiments/scripted-reference-comparison.json` is deterministic, harmless synthetic data. Its baseline side is a scripted control response and its contained side reflects the bounded synthetic runner's denial expectations. It is not a result from Nemesis, a real target, an autonomous attacker, or a frontier model. It does not measure persistence after teardown or verify an authoritative evidence chain, and it does not carry a certificate signature.
