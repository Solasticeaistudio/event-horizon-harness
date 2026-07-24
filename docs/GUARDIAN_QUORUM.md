# Guardian quorum and veto semantics

The guardian coordinator implements a unanimity veto, not a vote. The Static Policy Guardian, Executor Attestation Guardian, Lineage Budget Guardian, and Behavioral Transition Guardian are all required. Additional guardians may subtract authority, but their approval has no additive effect.

A request proceeds only when all of these conditions hold:

- every required guardian returns exactly one decision;
- every decision is a well-formed `GuardianDecision` for the same canonical request digest;
- every configured and additional guardian explicitly approves;
- the Static Policy Guardian explicitly approves and reports the coordinator's deterministic policy digest;
- any other reported policy digest equals that static version;
- no guardian times out, raises an exception, returns malformed output, or returns a stale or swapped response.

Missing decisions, duplicate identities, malformed output, crashes, timeouts, request-digest mismatches, policy-version inconsistencies, and every explicit denial are vetoes. Reordering does not change the result because identities and request bindings are checked independently of list position.

The static policy ceiling is evaluated directly against the immutable canonical request. Dynamic approvals are never interpreted as permissions and are not inputs to capability scope construction. The signer uses the exact request, the static-policy digest and output limit, and verified attestation bindings. If the Static Policy Guardian is absent or unavailable, no capability is issued.

The in-process timeout adapter uses a daemon thread and treats a late result as unusable. The process-separated harness additionally enforces RPC deadlines and denies on service failure. Availability is not a security fallback.
