# Canary capabilities

Canary capabilities are signed, test-only non-effect tripwires. They are a disjoint schema (`event-horizon.canary-capability.v1`) with IDs beginning `canary_`; executable capabilities use `cap_`. The executor checks the canary type before normal capability verification, records the attempt, and returns a denial without dispatching an effect.

The signed claims bind campaign, session, workload, tenant, environment, seed location, policy version, lifetime, and a digest of the exposed representation. Mutation and cross-workload use are classified as trusted events. Configured responses are selected from a fixed subtract-only set: deny, reduce budget, remove tools, revoke, require re-attestation, quarantine, terminate, request review, or request the hardware safe state.

Seeding is disabled unless `enabled=True`, and the issuer rejects `production=True`. Canaries must be placed only in synthetic fixtures. They must not be inserted into user data. The public-only verifier has no capability-signing key and can never convert a canary into executable authority.

The current implementation records signed-chain evidence through the logical recorder. A denial-certificate builder can classify a canary denial, but automatic certificate emission is not yet wired into every canary event path. Physical separation of the recorder remains future work.
