"""Stable functional identifiers emitted into security evidence."""

STATIC_POLICY_GUARDIAN = "static-policy-guardian"
EXECUTOR_ATTESTATION_GUARDIAN = "executor-attestation-guardian"
LINEAGE_BUDGET_GUARDIAN = "lineage-budget-guardian"
BEHAVIORAL_TRANSITION_GUARDIAN = "behavioral-transition-guardian"

REQUIRED_GUARDIANS = frozenset({
    STATIC_POLICY_GUARDIAN,
    EXECUTOR_ATTESTATION_GUARDIAN,
    LINEAGE_BUDGET_GUARDIAN,
    BEHAVIORAL_TRANSITION_GUARDIAN,
})
