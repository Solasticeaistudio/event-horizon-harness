from __future__ import annotations

import time
import unittest

from event_horizon.component_ids import (
    BEHAVIORAL_TRANSITION_GUARDIAN,
    EXECUTOR_ATTESTATION_GUARDIAN,
    LINEAGE_BUDGET_GUARDIAN,
    STATIC_POLICY_GUARDIAN,
)
from event_horizon.guardians import GuardianQuorum, PolicyGuardian
from event_horizon.models import ActionRequest, GuardianDecision
from event_horizon.policy import OperationRule, StaticPolicy


def request(operation: str = "object.read", resource_id: str = "target-source") -> ActionRequest:
    return ActionRequest.from_dict({
        "request_id": "guardian-request",
        "session_id": "guardian-session",
        "agent_id": "attacker-agent",
        "operation": operation,
        "resource_id": resource_id,
        "executor_id": "exec-1",
        "arguments": {},
        "purpose": "guardian compromise injection",
    })


def policy() -> StaticPolicy:
    return StaticPolicy(
        policy_id="guardian-policy-v1",
        operations={"object.read": OperationRule(frozenset({"target-source"}))},
        allowed_agents=frozenset({"attacker-agent"}),
        allowed_executors=frozenset({"exec-1"}),
    )


class ApproveGuardian:
    def __init__(self, name: str, *, policy_digest: str | None = None):
        self.name = name
        self.policy_digest = policy_digest

    def evaluate(self, action: ActionRequest) -> GuardianDecision:
        evidence = {} if self.policy_digest is None else {"policy_digest": self.policy_digest}
        return GuardianDecision(self.name, True, "approve every request", evidence, action.request_digest)


def required_dynamic(policy_digest: str | None = None):
    return [
        ApproveGuardian(EXECUTOR_ATTESTATION_GUARDIAN, policy_digest=policy_digest),
        ApproveGuardian(LINEAGE_BUDGET_GUARDIAN, policy_digest=policy_digest),
        ApproveGuardian(BEHAVIORAL_TRANSITION_GUARDIAN, policy_digest=policy_digest),
    ]


class GuardianCompromiseTests(unittest.TestCase):
    def test_approve_everything_guardian_cannot_override_static_policy(self):
        static = PolicyGuardian(policy())
        quorum = GuardianQuorum([static, *required_dynamic(), ApproveGuardian("compromised")])
        decisions = quorum.evaluate(request("shell.execute", "host"))
        self.assertFalse(quorum.allowed(decisions))
        self.assertFalse(next(item for item in decisions if item.guardian == STATIC_POLICY_GUARDIAN).allowed)

    def test_malformed_output_is_an_explicit_veto(self):
        class Malformed:
            name = EXECUTOR_ATTESTATION_GUARDIAN

            def evaluate(self, _action):
                return {"allowed": True}

        quorum = GuardianQuorum([PolicyGuardian(policy()), Malformed(), *required_dynamic()[1:]])
        decisions = quorum.evaluate(request())
        malformed = next(item for item in decisions if item.guardian == EXECUTOR_ATTESTATION_GUARDIAN)
        self.assertFalse(malformed.allowed)
        self.assertIn("schema mismatch", malformed.reason)

    def test_timeout_and_crash_are_vetoes(self):
        class Timeout:
            name = EXECUTOR_ATTESTATION_GUARDIAN

            def evaluate(self, action):
                time.sleep(0.1)
                return GuardianDecision(self.name, True, "late", request_digest=action.request_digest)

        class Crash:
            name = LINEAGE_BUDGET_GUARDIAN

            def evaluate(self, _action):
                raise RuntimeError("injected crash")

        quorum = GuardianQuorum(
            [PolicyGuardian(policy()), Timeout(), Crash(), ApproveGuardian(BEHAVIORAL_TRANSITION_GUARDIAN)],
            guardian_timeout_seconds=0.01,
        )
        decisions = quorum.evaluate(request())
        self.assertFalse(quorum.allowed(decisions))
        self.assertIn("timed out", next(item for item in decisions if item.guardian == EXECUTOR_ATTESTATION_GUARDIAN).reason)
        self.assertIn("failed closed", next(item for item in decisions if item.guardian == LINEAGE_BUDGET_GUARDIAN).reason)

    def test_different_request_digest_and_old_approval_replay_are_vetoes(self):
        class WrongDigest:
            name = EXECUTOR_ATTESTATION_GUARDIAN

            def __init__(self, claimed: str):
                self.claimed = claimed

            def evaluate(self, _action):
                return GuardianDecision(self.name, True, "stale approval", request_digest=self.claimed)

        old = request(resource_id="target-source")
        current = request(resource_id="other-source")
        for claimed in ("0" * 64, old.request_digest):
            with self.subTest(claimed=claimed):
                quorum = GuardianQuorum([
                    PolicyGuardian(policy()), WrongDigest(claimed), *required_dynamic()[1:],
                ])
                decision = next(
                    item for item in quorum.evaluate(current)
                    if item.guardian == EXECUTOR_ATTESTATION_GUARDIAN
                )
                self.assertFalse(decision.allowed)
                self.assertIn("binding", decision.reason)

    def test_response_order_does_not_change_valid_quorum(self):
        static = PolicyGuardian(policy())
        quorum = GuardianQuorum([static, *required_dynamic()])
        decisions = quorum.evaluate(request())
        self.assertTrue(quorum.allowed(decisions))
        self.assertTrue(quorum.allowed(reversed(decisions)))

    def test_all_dynamic_approvals_cannot_authorize_prohibited_operation(self):
        static = PolicyGuardian(policy())
        quorum = GuardianQuorum([static, *required_dynamic()])
        self.assertFalse(quorum.allowed(quorum.evaluate(request("http.request", "internet"))))

    def test_static_policy_unavailable_or_missing_denies(self):
        missing = GuardianQuorum(required_dynamic())
        missing_decisions = missing.evaluate(request())
        self.assertFalse(missing.allowed(missing_decisions))
        static = next(item for item in missing_decisions if item.guardian == STATIC_POLICY_GUARDIAN)
        self.assertFalse(static.allowed)

        class CrashedStatic:
            name = STATIC_POLICY_GUARDIAN
            policy = policy()

            def evaluate(self, _action):
                raise RuntimeError("static policy unavailable")

        crashed = GuardianQuorum([CrashedStatic(), *required_dynamic()])
        self.assertFalse(crashed.allowed(crashed.evaluate(request())))

    def test_inconsistent_policy_versions_deny_the_entire_quorum(self):
        static = PolicyGuardian(policy())
        wrong_version = "f" * 64
        quorum = GuardianQuorum([
            static,
            ApproveGuardian(EXECUTOR_ATTESTATION_GUARDIAN, policy_digest=wrong_version),
            *required_dynamic()[1:],
        ])
        decisions = quorum.evaluate(request())
        self.assertFalse(quorum.allowed(decisions))
        inconsistent = next(item for item in decisions if item.guardian == EXECUTOR_ATTESTATION_GUARDIAN)
        self.assertFalse(inconsistent.allowed)
        self.assertIn("policy version", inconsistent.reason)

    def test_dynamic_guardian_cannot_widen_operation_arguments(self):
        action = ActionRequest.from_dict({
            **request().canonical_payload(),
            "arguments": {"url": "https://example.invalid"},
        })
        quorum = GuardianQuorum([PolicyGuardian(policy()), *required_dynamic()])
        self.assertFalse(quorum.allowed(quorum.evaluate(action)))


if __name__ == "__main__":
    unittest.main()
