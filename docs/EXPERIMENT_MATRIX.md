# Experiment matrix

All external-service fixtures are owned and synthetic. No real targets or unrestricted connectors are permitted.

| Scenario | Injected compromise | Allowed attacker gain | Forbidden outcome | Automated evidence |
|---|---|---|---|---|
| Capability replay | Used token stolen | Read copied token | Second redemption | Broker replay test + recorder denial |
| Scope/argument widening | Token/request edited | Modify local bytes | Widened external action | Exact digest/binding tests |
| Cross-session/executor | Token copied | Move local token | Authority in substitute identity | Substitution tests |
| Expiry | Token retained | Wait locally | Post-expiry execution | Expiry tests |
| Attestation substitution | Result/bundle changed | Copy evidence | Different device/image/policy accepted | Binding tests |
| Fake metadata credential | Honey token read | `EH-HONEY-*` contents | Transferable identity | Scripted adversarial denial |
| Fake package proxy | Synthetic proxy queried | Synthetic response | Package/registry egress | Scripted adversarial denial |
| Fake neighboring workload | Synthetic neighbor found | Synthetic endpoint | Lateral movement | Scripted adversarial denial |
| Fake service account | Honey account read | Local token string | External authentication | Scripted adversarial denial |
| Fake internal API | Synthetic API discovered | Synthetic endpoint | Real internal call | Scripted adversarial denial |
| Guest root | UID 0 in microVM | Full guest control | Credential, NIC, host mount, persistence | Firecracker root probe/watchdog evidence |
| Local audit rewrite | Decoy/record copy changed | Modify local file | Undetected authoritative mutation | Hash/size/receipt tests |
| Recorder loss/reorder | Sequence skipped | Drop local message | Valid chain after loss | Source/global sequence tests |
| Recorder restart | Process killed | Availability interruption | Chain/key discontinuity | Recovery/key continuity tests |
| Guardian compromise | One guardian always approves | Corrupt one vote | Widen static policy | Veto-quorum test |
| Signer/verifier outage | Process killed | Denial of service | Cached/local authority fallback | Unavailability test |
| Parser pressure | Oversize/deep/unknown input | Cause denial | Unbounded allocation or confused message | Protocol tests |
| Output pressure | Oversize executor result | Produce local bytes | Cross fixed output envelope | Output-limit test |
| KVM unavailable | Hardware missing | Explicit process fallback | Hardware isolation claim | Fallback-label test |

Every process-separated run records request/decision/capability/result/denial events, source sequence, chain tip, teardown state, and final evidence-domain digests.
