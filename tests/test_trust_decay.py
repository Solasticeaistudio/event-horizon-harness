from __future__ import annotations

import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from event_horizon.canonical import digest
from event_horizon.models import ActionRequest, ValidationError
from event_horizon.trust_decay import (
    DecayAuthority,
    DecayEngine,
    DecayError,
    DecayProfile,
    DecayStep,
    InMemoryDecayStateStore,
    SqliteDecayStateStore,
)


def request() -> ActionRequest:
    return ActionRequest(
        request_id="request-1",
        session_id="session-1",
        agent_id="agent-1",
        operation="object.read",
        resource_id="source-1",
        executor_id="executor-1",
        arguments={"length": 1},
        purpose="decay test",
    )


def authority(*, calls: int = 10, expires: int = 10_000) -> DecayAuthority:
    return DecayAuthority(
        expires_at_ms=expires,
        remaining_calls=calls,
        remaining_read_bytes=1_000,
        remaining_write_bytes=100,
        network_destinations=("synthetic.service",),
        tools=("object-reader",),
        actions=("object.read",),
        resources=("source-1",),
        argument_ranges={"length": (0, 10)},
        maximum_parallelism=4,
        maximum_effect_severity=5,
    )


def profile(*steps: DecayStep, calls: int = 10, expires: int = 10_000) -> DecayProfile:
    return DecayProfile("test-decay", "v1", authority(calls=calls, expires=expires), steps)


class TrustDecayTests(unittest.TestCase):
    def test_time_decay_is_applied_before_first_late_redemption(self) -> None:
        engine = DecayEngine()
        timed = profile(DecayStep("elapsed_ms", 50, remove_actions=("object.read",)))
        with self.assertRaisesRegex(DecayError, "denies"):
            engine.authorize("cap-time", timed, request(), issued_at_ms=1_000, now_ms=1_051)

    def test_use_and_data_decay_are_monotonic(self) -> None:
        engine = DecayEngine()
        limited = profile(DecayStep("use_count", 2, maximum_read_bytes=10), calls=3)
        first = engine.authorize(
            "cap-use", limited, request(), issued_at_ms=1_000, now_ms=1_001, read_bytes=4
        )
        second = engine.authorize(
            "cap-use", limited, request(), issued_at_ms=1_000, now_ms=1_002, read_bytes=4
        )
        self.assertTrue(second.resulting_state.current_authority.is_subset_of(
            first.resulting_state.current_authority
        ))
        self.assertEqual(second.resulting_state.current_authority.remaining_calls, 1)
        self.assertEqual(second.resulting_state.current_authority.remaining_read_bytes, 10)

    def test_risk_and_canary_events_reduce_before_effect(self) -> None:
        engine = DecayEngine()
        risky = profile(
            DecayStep("risk_score", 4, maximum_calls=0),
            DecayStep("canary_events", 1, maximum_calls=0),
        )
        with self.assertRaises(DecayError):
            engine.authorize(
                "cap-risk", risky, request(), issued_at_ms=1_000, now_ms=1_001, risk_score=4
            )
        with self.assertRaises(DecayError):
            engine.authorize(
                "cap-canary", risky, request(), issued_at_ms=1_000, now_ms=1_001,
                canary_events=1,
            )

    def test_no_decay_steps_preserve_scope_but_use_budget_decreases(self) -> None:
        result = DecayEngine().authorize(
            "cap-none", profile(calls=2), request(), issued_at_ms=1_000, now_ms=1_001
        )
        self.assertEqual(result.authorized_authority.actions, ("object.read",))
        self.assertEqual(result.resulting_state.current_authority.remaining_calls, 1)

    def test_malformed_profile_and_expansion_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            DecayStep("unknown-trigger", 1)
        malformed = profile().to_dict()
        malformed["unknown"] = True
        with self.assertRaises(ValidationError):
            DecayProfile.from_dict(malformed)
        wider = profile(calls=11)
        engine = DecayEngine()
        engine.authorize("cap-profile", profile(), request(), issued_at_ms=1_000, now_ms=1_001)
        with self.assertRaisesRegex(DecayError, "substitution"):
            engine.authorize("cap-profile", wider, request(), issued_at_ms=1_000, now_ms=1_002)

    def test_clock_rollback_never_restores_authority(self) -> None:
        engine = DecayEngine()
        configured = profile(DecayStep("elapsed_ms", 50, maximum_parallelism=1))
        first = engine.authorize(
            "cap-clock", configured, request(), issued_at_ms=1_000, now_ms=1_060
        )
        second = engine.authorize(
            "cap-clock", configured, request(), issued_at_ms=1_000, now_ms=1_020
        )
        self.assertTrue(second.clock_rollback_observed)
        self.assertEqual(second.authorized_authority.maximum_parallelism, 1)
        self.assertTrue(second.resulting_state.current_authority.is_subset_of(
            first.resulting_state.current_authority
        ))

    def test_clock_jump_and_expiration_fail_closed(self) -> None:
        with self.assertRaisesRegex(DecayError, "denies"):
            DecayEngine().authorize(
                "cap-expired", profile(expires=2_000), request(),
                issued_at_ms=1_000, now_ms=2_000,
            )

    def test_sqlite_restart_preserves_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decay.sqlite3"
            first_store = SqliteDecayStateStore(path)
            DecayEngine(first_store).authorize(
                "cap-restart", profile(), request(), issued_at_ms=1_000, now_ms=1_001
            )
            first_store.close()
            second_store = SqliteDecayStateStore(path)
            restored = second_store.load("cap-restart")
            self.assertIsNotNone(restored)
            self.assertEqual(restored.use_count, 1)
            second_store.close()

    def test_concurrent_redemption_budget_allows_exactly_one(self) -> None:
        engine = DecayEngine(InMemoryDecayStateStore())
        one_use = profile(calls=1)
        barrier = threading.Barrier(64)
        results: list[bool] = []
        lock = threading.Lock()

        def attempt() -> None:
            barrier.wait()
            try:
                engine.authorize(
                    "cap-race", one_use, request(), issued_at_ms=1_000, now_ms=1_001
                )
                value = True
            except DecayError:
                value = False
            with lock:
                results.append(value)

        threads = [threading.Thread(target=attempt) for _ in range(64)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count(True), 1)

    def test_state_store_partition_fails_closed(self) -> None:
        class Unavailable:
            def load(self, capability_id):  # pragma: no cover - protocol completeness
                raise OSError("partition")

            def update(self, capability_id, transition):
                raise OSError("partition")

        with self.assertRaisesRegex(DecayError, "unavailable"):
            DecayEngine(Unavailable()).authorize(
                "cap-partition", profile(), request(), issued_at_ms=1_000, now_ms=1_001
            )

    def test_refresh_requires_new_identity_and_fresh_trusted_inputs(self) -> None:
        engine = DecayEngine()
        valid = digest({"fresh": 1})
        with self.assertRaises(DecayError):
            engine.refresh(
                "cap-old", "cap-old", profile(),
                fresh_attestation_digest=valid, fresh_authorization_digest=valid,
            )
        with self.assertRaises(DecayError):
            engine.refresh(
                "cap-old", "cap-new", profile(),
                fresh_attestation_digest="not-a-digest", fresh_authorization_digest=valid,
            )
        refreshed = engine.refresh(
            "cap-old", "cap-new", profile(),
            fresh_attestation_digest=valid, fresh_authorization_digest=digest({"fresh": 2}),
        )
        self.assertEqual(refreshed.use_count, 0)
        with self.assertRaisesRegex(DecayError, "stale refresh"):
            engine.refresh(
                "cap-old", "cap-new", profile(),
                fresh_attestation_digest=valid, fresh_authorization_digest=valid,
            )

    def test_attempts_to_reset_counters_or_replace_profile_fail(self) -> None:
        store = InMemoryDecayStateStore()
        engine = DecayEngine(store)
        configured = profile()
        state = engine.authorize(
            "cap-reset", configured, request(), issued_at_ms=1_000, now_ms=1_001
        ).resulting_state
        with self.assertRaises(DecayError):
            store.update(
                "cap-reset",
                lambda prior: replace(state, use_count=0, current_authority=authority(calls=10)),
            )
        with self.assertRaisesRegex(DecayError, "substitution"):
            engine.authorize(
                "cap-reset", profile(DecayStep("denials", 1, maximum_calls=0)), request(),
                issued_at_ms=1_000, now_ms=1_002,
            )


if __name__ == "__main__":
    unittest.main()
