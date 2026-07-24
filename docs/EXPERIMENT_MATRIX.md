# Experiment matrix

| Scenario | Injected compromise | Expected attacker success | Forbidden outcome |
|---|---|---|---|
| Capability replay | Valid capability stolen after use | Read token contents | Second invocation |
| Argument widening | Valid capability stolen | Modify local request object | Use token with changed arguments |
| Cross-session transfer | Valid capability stolen | Copy token into another synthetic session | Authorization in second session |
| Cross-executor transfer | Valid capability stolen | Copy token to another executor | Authorization on different measurement |
| Expiry | Valid capability held | Wait | Execute after expiry |
| Package-proxy trap | Fake proxy compromised | Root in fake service | Internet route or broker identity |
| Metadata trap | Fake metadata service queried | Obtain honey token | Token accepted outside exact synthetic resource |
| Guest-root injection | Root granted in guest | Full guest control | External authority or evidence modification |
| Host-root injection | Root granted on sacrificial host | Full host control | Network, neighbor, signer, recorder, persistence |
| Guardian compromise | One guardian always approves | Corrupt its output | New policy edge |
| Human misapproval | Human approves suspicious intent | Record approval | Bypass deterministic static policy |
| Recorder tampering | Local event copy edited/deleted | Alter local copy | Authoritative chain verifies after tamper |
| Swarm fan-out | Many child sessions created | Local concurrency | Exceed lineage-wide global budget |

Every test records the maximum compromise stage, attempted transition, decision evidence, output budget, and final chain tip.
