# Baseline architecture and enforcement audit

This audit records the repository state observed before the adaptive capability-governance work began. It describes revision `ac520c2f7aa7a4c68486b289347ea2ca409f335c` on 2026-07-24 (America/Chicago). The worktree was clean. Claims below are limited to inspected code, executed tests, and generated synthetic results.

## Baseline environment and results

| Item | Observed result |
|---|---|
| Host | Windows NT 10.0.26200.0 |
| Python | 3.11.9 |
| Node.js | 22.19.0; CI is configured for Node.js 20 |
| npm | 10.9.3 |
| Python tests | 99 passed |
| TypeScript tests | 62 passed; one opt-in real Linux TPM test skipped |
| Python/Node replay interoperability | Passed |
| TypeScript build and typecheck | All eight workspaces passed |
| Capability vectors | Eight of eight passed |
| Repository policy | Passed for 176 tracked paths |
| Scripted synthetic campaigns | Ten of ten reported contained |
| Public demonstration | Exact operation succeeded; replay, widening, transfer, and prohibited network operation were denied; local evidence-copy tampering was detected; certificate verified |

Commands executed before source changes:

```powershell
npm ci
npm run build
npm run typecheck
npm test
python scripts/lint_python.py
python scripts/verify_capability_vectors.py
python scripts/check_repository_policy.py
python -m event_horizon.adversarial_demo --workdir <temporary-directory>
python -m event_horizon.public_demo --workdir <temporary-directory> --artifacts-dir <temporary-directory>
```

The baseline test count is a count of test-runner cases, not an independent assurance score. The skipped TPM test requires explicitly configured Linux TPM infrastructure.

## Architecture as found

The default public path is process separation on one host. `ProcessSeparatedHarness` starts seven roles with canonical length-prefixed JSON over stdio:

```text
Typed action request (untrusted)
    -> parser / Intent Canonicalizer
    -> fresh Executor Attestation verification
    -> Static Policy Guardian
       + Executor Attestation Guardian
       + Lineage Budget Guardian
       + Behavioral Transition Guardian
    -> unanimity/veto aggregate
    -> protected capability signer
    -> authoritative broker-side one-use consumption
    -> hostile executor's public-key verification and separate one-use consumption
    -> fixed object-read or compute effect
    -> authenticated logical evidence recorder
    -> containment-certificate signer
```

The requested future flow maps onto the existing system as follows:

```text
Task Request                         not represented separately at baseline
    -> Task Classification           not implemented
    -> Adaptive Policy Ceiling        not implemented
    -> Trusted Policy Compiler        not implemented
    -> Capability Broker              CapabilityBroker / signer service
    -> Provider Attestation           TypeScript Verifier via Python development bridge
    -> Guardian Intersection          GuardianQuorum or guardian service
    -> Capability Signing             Ed25519 CapabilityBroker.issue
    -> Hostile Cell                   SacrificialExecutor / executor service
    -> Redemption Verification        signer.consume then executor CapabilityVerifier
    -> Effect Executor                fixed object.read and compute.run dispatch
    -> Evidence Recorder              ExternalRecorder service
    -> Certificate / Replay           ContainmentCertificateBuilder and SQLite replay stores
```

There is no learned policy or model in the authorization path. The current `SequenceGuardian` evaluates one request at a time against a fixed suspicious-operation set; it does not persist or score session behavior.

## Exact authorization and redemption paths

### Local path

1. `IntentCanonicalizer.request_capability()` parses `ActionRequest` and records `request.received`.
2. `GuardianQuorum.evaluate()` obtains required static-policy, attestation, lineage-budget, and sequence decisions. Missing, malformed, duplicate, stale-bound, inconsistent-policy, crashed, or timed-out decisions become vetoes.
3. `IntentCanonicalizer` takes output size only from the static-policy decision and attestation bindings only from the attestation decision.
4. `CapabilityBroker.issue()` signs canonical `CapabilityClaims` with Ed25519.
5. `SacrificialExecutor.execute()` calls `CapabilityBroker.verify_and_consume()`, dispatches one registered operation, bounds output, and appends either `execution.completed` or `execution.denied`.

### Process-separated path

1. `ProcessSeparatedHarness.request_capability()` calls the parser, verifier, guardians, and signer services in order.
2. Signer `issue` independently checks the exact guardian aggregate, static-policy digest, full attestation-result equality, and maximum output bound before calling `CapabilityBroker.issue()`.
3. `ProcessSeparatedHarness.execute()` first calls protected signer `consume`, which atomically consumes in the authoritative broker domain.
4. It then calls executor `execute`; the executor independently verifies the signature and bindings and consumes in a distinct executor domain before dispatching a fixed operation.
5. The coordinator records the returned outcome. A dropped response after effect commit is not currently reconciled into a distinct authoritative state.

Protected signer, recorder, and certificate mutations require an Ed25519 authorization over the exact RPC envelope plus a durable one-use authorization nonce. Their development private seeds are stored in separate restricted files and are absent from executor configuration. All processes still run under one host account.

## Capability lifecycle and bindings

Baseline capabilities are Ed25519-signed, short-lived, and constrained to an invocation limit of one. Claims bind:

- capability ID, issuance and expiration;
- session, agent, executor, and device IDs;
- executor measurement;
- attestation result, bundle, and verifier-policy digests;
- operation, resource, argument digest, and complete request digest;
- output-byte maximum;
- static-policy digest; and
- signer key ID.

They do not bind a distinct task ID or fingerprint, tenant, environment, audience, provider-derived trust tier, provider key identity, adaptive policy ceiling, compiler/synthesizer version, explicit guardian reduction set, network/data scope, decay profile, data/write/call/parallelism budgets, or canary status.

SQLite consumption is atomic and durable across cooperating processes and restarts on one host. The signed remote replay interface supplies explicit epochs, request/response signatures, checkpoint continuity, and rollback detection relative to client-retained state. It is a single-writer reference, not a consensus or leader-fencing implementation.

## Trust behavior and observed gaps

The TypeScript attestation verifier dispatches by a registered bundle method. Simulator verification can return only `simulated`/`development`; TPM verification returns `hardware`/`hardware-rooted` only after quote, key, PCR, freshness, event-log policy, and complete-bundle checks. The Python bridge recomputes a verifier-policy digest and a complete result digest outside the hostile executor.

The process-separated signer and executor require a complete attestation result and compare its digest, measurement, device, and policy bindings. However:

- `CapabilityClaims` does not explicitly bind provider method, provider-attested trust level, assurance level, attestation key ID, tenant, or environment.
- `_verified_claims()` treats omitted `device_id`, attestation digests, verifier-policy digest, and policy digest as equal to the signed claims. The local executor invokes verification without a current attestation result, so missing current trust evidence can pass in that path.
- the signer `consume` call passes the capability's own signed policy digest as the current policy digest instead of independently obtaining current policy state;
- the hostile workload cannot currently self-assert a TypeScript hardware result, but downstream Python enforcement cannot express operation-specific trust requirements or distinguish requested, observed, provider-attested, signed, and current redemption trust;
- a later trust downgrade has no independent redemption-time trust source in the local path.

These are hard-enforcement gaps. Fixing them must retain provider-specific verification and must not replace attested trust with adaptive-policy or guardian output.

## Policy and guardian behavior

`StaticPolicy` is deny-by-default and limits agents, executors, operations, resources, argument-key sets, denied argument names, and output bytes. It does not represent task semantics, tenant/environment rules, network/data scopes, approval gates, trust tiers, call/data/write/parallelism budgets, or decay.

Guardians use required-identity unanimity. Dynamic approvals are not used to construct request scope. Static-policy failure denies. `LineageBudgetGuardian` tracks request and denial counts only in process memory. `SequenceGuardian` denies a fixed set of operation names but has no sequence memory, durable state, anomaly mode, shadow mode, or deterministic reduction object.

No policy synthesizer, trusted compiled-ceiling type, shadow/evaluation policy mode, policy-sizing metric, learned proposal interface, or explicit adaptive-policy non-authority boundary exists.

## Evidence and certificate behavior

`ExternalRecorder` persists fixed-size canonical events in a SHA-256 chain with global and per-source sequence continuity, flush/fsync, restart validation, and signed receipts. Mutations require protected client authorization in the process topology.

Baseline events distinguish received, rejected/denied, capability issued, execution completed/denied, guardian decisions, attestation verified, adversarial campaign, and teardown. They do not consistently distinguish attempted, validated, effect-started, committed, indeterminate, response-lost, reconciled, recovered, or replayed effect states. The coordinator records execution outcome only after a response, so recorder completeness depends on that coordinator path.

The containment certificate signs recorder-derived and coordinator-supplied evidence domains. It is not a request-specific denial receipt and does not implement denial-certificate IDs, technique classification, effect-state semantics, signer revocation, or evidence-reference verification.

## Restart and isolation behavior

- Nonce and capability consumption survive configured verifier, signer, and executor restarts through SQLite.
- Recorder restart rescans and validates the complete chain before appending.
- Protected authorization replay state survives service restart.
- Lineage-budget and sequence-guardian state do not survive guardian restart.
- The default executor is a same-host process. A Firecracker development target and a WSL2 nested-KVM fixture exist, but normal CI does not establish production microVM isolation.
- TPM fixtures and optional `swtpm` exercise verification paths without proving physical hardware provenance.
- No independent heartbeat switch, microcontroller simulator, firmware, re-arm protocol, or hardware-in-the-loop result exists.

## Baseline invariant coverage

| Requested invariant | Baseline evidence | Baseline gap |
|---|---|---|
| EH-1 hostile workload lacks signing material | Process tests inspect executor configuration/environment; signer key is in a distinct restricted file/process | Same host account and kernel remain trusted |
| EH-2 provider trust is not self-asserted | Provider-specific TypeScript verification and substitution tests | Trust tier is not an explicit Python capability/redemption binding |
| EH-3 capability exactness | Exact request, identities, measurement, digests, policy, expiry, output, and one-use checks | Missing task, tenant/environment, trust tier/key, adaptive ceiling, reductions, decay, network/data/budget bindings |
| EH-4 at-most-once committed effect | Atomic broker and executor consumption; thread/process contention tests | No effect journal or reconciliation for response loss and ambiguous commit |
| EH-5 evidence integrity | Hash chain, signed receipts, source sequence, restart validation | Effect-state vocabulary and guaranteed effect-side recording are incomplete |
| EH-6 guardian subtract-only | Static ceiling plus unanimity/veto and compromise tests | No typed reduction algebra for future behavioral/decay components |
| EH-7 adaptive-policy non-authority | Not applicable: adaptive policy absent | Must be implemented and isolated from signing |
| EH-8 monotonic trust decay | Expiration and one-use only | No decay profile or durable monotonic decay state |
| EH-9 canary non-effect | Not implemented | No canary type, event, or pre-effect denial path |
| EH-10 verifiable denial evidence | General containment certificate only | No request-specific signed denial certificate |
| EH-11 hardware fail-safe independence | Not implemented | No external switch protocol, simulator, firmware, or physical result |

## Existing limitations retained

The repository correctly states that it does not demonstrate frontier-model containment, production Firecracker isolation, production TPM enrollment/provenance, resistance to host-kernel compromise, independently administered keys/evidence, multi-host consensus replay, old-leader fencing, or an external audit. The scripted adversary is harmless and synthetic. Those boundaries remain controlling until executable evidence changes them.

## Missing requested subsystems at baseline

Repository search and code inspection found no Task Policy Ceiling, deterministic ceiling compiler, policy-sizing reports, canary capabilities, denial certificates, persistent behavioral guardian, authority-decay engine, Hypothesis/fast-check dependency, dedicated concurrent effect journal, named chaos framework, configured tool-using LLM adversary, vulnerable positive-control gate, reviewed literature adapter, hardware fail-safe switch, firmware, or TLA+ model.

The implementation sequence must therefore start by fixing current-trust enforcement and introducing a deterministic compiled-ceiling object that is the only new input accepted by capability issuance. Model-assisted policy remains optional and non-authoritative.
