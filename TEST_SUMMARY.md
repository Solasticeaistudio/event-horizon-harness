# Test summary

Validated on July 23, 2026:

- Event Horizon Python authority and integration suite: **13 passed**
- Executor Attestation Node/TypeScript suite: **7 passed**
- Combined: **20 passed, 0 failed**

Covered behaviors include:

- exact capability use;
- replay denial;
- argument widening denial;
- cross-session and cross-executor denial;
- expiry denial;
- malformed request rejection;
- prohibited operation denial;
- permissive guardian unable to widen policy;
- recorder tamper detection;
- Executor Attestation signature validation;
- nonce mismatch rejection;
- proof replay rejection;
- measurement policy rejection;
- unknown-device fail-closed behavior;
- SDK bundle encoding and local verification;
- Ed25519 Containment Certificate verification and tamper rejection.
