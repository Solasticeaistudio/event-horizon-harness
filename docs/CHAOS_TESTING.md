# Deterministic chaos and recovery testing

The fault catalogue names 50 signer, synthesizer, compiler, executor, recorder, capability-store, guardian, attestation, and network points. Every point maps to one explicit disposition: deny, safe retry, reconcile, indeterminate, or halt. The injector is inert by default and refuses to enable outside `environment="test"`.

The real executor exposes test-only hooks before/after validation, before/after effect, around evidence recording, and before response. A fault after effect is returned as `execution.indeterminate`; it is never relabeled as a denial. The deterministic classifier likewise prohibits retry wherever an effect is committed or uncertain.

Run `make test-chaos`. The catalogue currently tests state classification and executor hooks. Not every named point is yet wired as a live hook in every production component, and process-kill/filesystem fault campaigns remain future work.
