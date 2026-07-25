# Reviewed literature and benchmark feed

External research enters only as bounded metadata:

```text
source metadata -> normalized technique -> human review queue
                -> approved safe campaign template -> isolated fixture
```

The adapter never downloads or executes source code, proof-of-concept exploits, datasets, or credentials. It rejects unknown fields and unsafe simulation language. Default tests load a pinned local fixture and require no network. `python scripts/check_literature_feed.py --live` retrieves only the current GitHub commit metadata and reports version/hash/license drift; it does not update or approve anything.

The first fixture maps six metadata-only techniques from SandboxEscapeBench commit `12952e8d7c0013adb9a95165c2a4b99d6ca22aa6`, whose repository declares the MIT license. The source paper is arXiv:2603.02277. All six entries remain `pending-human-review`, so no imported campaign is executed or represented as approved. The safe simulations are configuration and policy checks, not exploit reproductions.

The generic schema supports sandbox escape, agent tool security, capability/least privilege, prompt injection, MCP/tool protocols, and runtime/orchestration/kernel categories. Adapters for categories other than SandboxEscapeBench are not yet implemented.
