from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from event_horizon.behavioral_guardian import (
    BehavioralGuardian,
    InMemoryBehavioralStateStore,
    SqliteBehavioralStateStore,
    behavioral_evaluation_report,
)
from event_horizon.models import ActionRequest


def action(
    index: int = 0,
    *,
    session: str = "session-a",
    executor: str = "executor-a",
    resource: str = "target-a",
    value: int = 1,
) -> ActionRequest:
    return ActionRequest(
        f"request-{index}", session, "agent-a", "object.read", resource,
        executor, {"value": value}, "legitimate synthetic analysis",
    )


class _Model:
    version = "test-model-v1"

    def __init__(self, output=None, error=None):
        self.output = output
        self.error = error

    def score(self, _state, _request):
        if self.error:
            raise self.error
        return self.output


class BehavioralGuardianTests(unittest.TestCase):
    def test_ordinary_repeated_legitimate_operations_and_timeout_retry(self) -> None:
        guardian = BehavioralGuardian(InMemoryBehavioralStateStore())
        for index in range(5):
            decision = guardian.evaluate_context(action(index), now_ms=1_000 + index * 100)
            self.assertTrue(decision.allowed)
            self.assertEqual(decision.evidence["risk_score"], 0)
        guardian.record_outcome(action(5), "timeout", now_ms=2_000)
        retry = guardian.evaluate_context(action(6), now_ms=2_100)
        self.assertTrue(retry.allowed)
        self.assertNotIn("rapid-retry-after-denial", retry.evidence["signals"])

    def test_systematic_one_parameter_probing_is_reduced_then_quarantined(self) -> None:
        guardian = BehavioralGuardian(InMemoryBehavioralStateStore())
        guardian.evaluate_context(action(0, value=1), now_ms=1_000)
        second = guardian.evaluate_context(action(1, value=2), now_ms=2_000)
        self.assertIn("one-field-mutation", second.evidence["signals"])
        third = guardian.evaluate_context(action(2, value=3), now_ms=3_000)
        self.assertTrue(third.allowed)
        self.assertIn("authority_reduction", third.evidence)
        fourth = guardian.evaluate_context(action(3, value=4), now_ms=4_000)
        self.assertFalse(fourth.allowed)
        self.assertTrue(fourth.evidence["authority_reduction"]["revoke"])

    def test_distributed_slow_resource_and_cross_workload_probing(self) -> None:
        guardian = BehavioralGuardian(InMemoryBehavioralStateStore(), slow_probe_window_ms=1_000)
        guardian.evaluate_context(action(0), now_ms=1_000, worker_id="worker-a")
        guardian.record_outcome(action(0), "denied", now_ms=1_000)
        distributed = guardian.evaluate_context(
            action(1, value=2), now_ms=1_100, worker_id="worker-b"
        )
        self.assertIn("distributed-probing", distributed.evidence["signals"])

        slow = BehavioralGuardian(InMemoryBehavioralStateStore(), slow_probe_window_ms=1_000)
        for index in range(4):
            slow.evaluate_context(action(index, session="slow"), now_ms=1_000 + index * 100)
        decision = slow.evaluate_context(action(4, session="slow"), now_ms=3_000)
        self.assertIn("slow-probing", decision.evidence["signals"])

        cross = BehavioralGuardian(InMemoryBehavioralStateStore())
        cross.evaluate_context(action(0), now_ms=1_000)
        decision = cross.evaluate_context(action(1, executor="executor-b"), now_ms=2_000)
        self.assertFalse(decision.allowed)
        self.assertIn("workload-mutation", decision.evidence["signals"])

    def test_resource_enumeration_repeated_denials_and_canary_interaction(self) -> None:
        guardian = BehavioralGuardian(InMemoryBehavioralStateStore())
        first = action(0)
        guardian.evaluate_context(first, now_ms=1_000)
        guardian.record_outcome(first, "denied", now_ms=1_000)
        second = action(1, resource="target-b")
        guardian.evaluate_context(second, now_ms=1_500)
        guardian.record_outcome(second, "denied", now_ms=1_500)
        decision = guardian.evaluate_context(
            action(2, resource="target-c"), now_ms=1_600
        )
        self.assertIn("resource-enumeration", decision.evidence["signals"])
        self.assertIn("repeated-denials", decision.evidence["signals"])
        self.assertFalse(decision.allowed)

        canary = BehavioralGuardian(InMemoryBehavioralStateStore())
        state = canary.record_security_signal(
            "canary-session", "canary-interaction", now_ms=1_000
        )
        self.assertTrue(state.quarantined)
        denied = canary.evaluate_context(
            action(3, session="canary-session"), now_ms=2_000
        )
        self.assertFalse(denied.allowed)

    def test_state_survives_restart_and_is_shared_across_guardian_instances(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "behavior.sqlite3"
            first_store = SqliteBehavioralStateStore(path)
            first = BehavioralGuardian(first_store)
            first.evaluate_context(action(0, value=1), now_ms=1_000)
            first_store.close()
            second_store = SqliteBehavioralStateStore(path)
            second = BehavioralGuardian(second_store)
            decision = second.evaluate_context(action(1, value=2), now_ms=2_000)
            self.assertIn("one-field-mutation", decision.evidence["signals"])
            self.assertEqual(second_store.load("default", "session-a").request_count, 2)
            second_store.close()

    def test_corrupt_state_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "behavior.sqlite3"
            store = SqliteBehavioralStateStore(path)
            store.update("default", "session-a", lambda state: state)
            store.close()
            connection = sqlite3.connect(path)
            connection.execute(
                "UPDATE behavioral_state SET payload_digest=?", ("0" * 64,)
            )
            connection.commit()
            connection.close()
            reopened = SqliteBehavioralStateStore(path)
            decision = BehavioralGuardian(reopened).evaluate_context(action(), now_ms=1_000)
            self.assertFalse(decision.allowed)
            self.assertIn("state unavailable", decision.reason)
            reopened.close()

    def test_model_outage_and_compromised_additive_output_fail_closed(self) -> None:
        outage = BehavioralGuardian(
            InMemoryBehavioralStateStore(), mode="anomaly",
            model=_Model(error=RuntimeError("offline")),
        )
        self.assertFalse(outage.evaluate_context(action(), now_ms=1_000).allowed)
        additive = BehavioralGuardian(
            InMemoryBehavioralStateStore(), mode="anomaly",
            model=_Model({"risk_delta": 0, "reduction": {"add_tools": ["shell"]}}),
        )
        decision = additive.evaluate_context(action(), now_ms=1_000)
        self.assertFalse(decision.allowed)
        self.assertIn("non-subtractive", decision.reason)

    def test_valid_model_reduction_is_validated_and_shadow_never_enforces_it(self) -> None:
        reduction = {
            "source": "model", "remove_tools": ["safe-compute"], "remove_actions": [],
            "remove_resources": [], "remove_network_destinations": [],
            "maximum_read_bytes": None, "maximum_write_bytes": 0, "maximum_calls": 1,
            "maximum_parallelism": 1, "maximum_duration_seconds": 10,
            "require_reattestation": False, "require_human_approval": False, "revoke": False,
        }
        model = _Model({"risk_delta": 10, "reduction": reduction})
        anomaly = BehavioralGuardian(InMemoryBehavioralStateStore(), mode="anomaly", model=model)
        enforced = anomaly.evaluate_context(action(), now_ms=1_000)
        self.assertEqual(enforced.evidence["authority_reduction"]["maximum_calls"], 1)
        shadow = BehavioralGuardian(InMemoryBehavioralStateStore(), mode="shadow", model=model)
        observed = shadow.evaluate_context(action(), now_ms=1_000)
        self.assertNotIn("authority_reduction", observed.evidence)
        self.assertEqual(observed.evidence["shadow_reduction"]["maximum_calls"], 1)

    def test_recovery_requires_new_trusted_event(self) -> None:
        guardian = BehavioralGuardian(InMemoryBehavioralStateStore())
        guardian.record_security_signal("session-a", "canary-interaction", now_ms=1_000)
        with self.assertRaises(PermissionError):
            guardian.recover("session-a")
        reattested = guardian.recover("session-a", trusted_reattestation=True)
        self.assertFalse(reattested.quarantined)
        guardian.record_security_signal("session-a", "canary-interaction", now_ms=2_000)
        approved = guardian.recover("session-a", human_approved=True)
        self.assertFalse(approved.quarantined)

    def test_detection_and_false_positive_rates_are_reported(self) -> None:
        report = behavioral_evaluation_report(
            [True, True, False, False], [True, False, False, True]
        )
        self.assertEqual(report["detection_rate_millis"], 500)
        self.assertEqual(report["false_positive_rate_millis"], 500)


if __name__ == "__main__":
    unittest.main()
