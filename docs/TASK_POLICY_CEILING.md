# Task Policy Ceiling

Event Horizon computes a task-specific least-authority ceiling and then enforces that ceiling through cryptographically bound, attestation-aware, subtract-only capabilities.

The Task Policy Synthesizer is not an authorization service. Its output is an untrusted candidate. It has no signing key, cannot mint a capability, and cannot bypass the deterministic compiler. Natural-language task text participates in the task fingerprint but never selects tools directly.

## Inputs and output

`TaskDescription` binds a task ID, subject, workload, natural-language purpose, trusted structured task type, tenant, environment, bounded tool and resource catalogues, data classification, approved constraints, static-policy version, provider-derived trust, optional approved template and trace references, deadline, and approval requirements.

`CandidateTaskPolicyCeiling` is a strict, unknown-field-rejecting proposal. Confidence uses integer basis points rather than floating point. It covers tools, actions, action-to-resource relationships, argument keys, network destinations, data classes, byte/call/parallelism/duration limits, required trust and attestations, approval gates, decay profile, rationale codes, and evidence references. It is never executable authority.

Supported modes are:

- `static`: deterministic approved task templates; no model is required.
- `rule`: templates plus deterministic risk reductions.
- `model`: an explicitly configured, versioned proposal model with a bounded timeout.
- `shadow`: computes a proposal while a separate static synthesizer supplies enforcement input.
- `evaluation`: deterministic proposal generation for comparison with references.

Unknown tasks, malformed model output, low confidence, model exceptions, and timeouts select a configured conservative fallback. The default fallback is denial. A model thread is bounded by a timeout, but Python cannot forcibly terminate an already executing model thread; deployments should isolate external model clients in a separately bounded process.

## Metrics

`evaluate_policy_sizing` records exposed/invoked tools and actions, dangerous and unnecessary exposure, omitted requirements, completion, under-provisioning, escalation and approval counts, latency, attack outcome, false denial, risk-weighted exposure, Skill Economy Ratio, and a composite score.

Skill Economy Ratio is represented as integer thousandths:

```text
SER = required-or-invoked tools / exposed tools
```

SER is not optimized alone. Zero exposure can prevent task completion, and observed invocation is only a lower-quality proxy for minimum necessary authority: a task may require a contingency permission that a particular trace did not exercise.

## Current integration

The local and process-separated capability paths use deterministic rule mode. Trusted code maps `object.read`, `compute.run`, and `deployment.apply` to structured task types. The exact requested action, resource, and argument-key set are carried as structured constraints and still must pass the template action set and static global maximum. Learned mode is optional and is not used by default CI or the public demo.
