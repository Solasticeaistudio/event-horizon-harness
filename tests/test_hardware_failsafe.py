from __future__ import annotations

import copy
import unittest

from event_horizon.canonical import digest
from event_horizon.hardware_failsafe import (
    FailSafeHostClient,
    HardwareFailSafeError,
    HardwareFailSafeSimulator,
)


NOW = 2_000_000_000_000


class HardwareFailSafeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = FailSafeHostClient("switch-1", b"hardware-simulator-test-key-no-authority")
        self.evidence = digest({"evidence": 1})
        counter = iter(f"{value:032x}" for value in range(1, 100))
        self.switch = HardwareFailSafeSimulator(
            device_id="switch-1",
            trusted_public_key_pem=self.client.public_key_pem,
            expected_policy_version="policy-v1",
            expected_evidence_digest=self.evidence,
            heartbeat_timeout_ms=1_000,
            nonce_factory=lambda: next(counter),
        )

    def send(self, *, action="heartbeat", now=NOW, payload=None, rearm=False, client=None, **changes):
        challenge = self.switch.issue_challenge(now)
        message = (client or self.client).respond(
            challenge, now_ms=now, policy_version=changes.pop("policy", "policy-v1"),
            evidence_chain_digest=changes.pop("evidence", self.evidence),
            action=action, action_payload=payload,
        )
        value = message.to_dict()
        value["claims"].update(changes)
        return self.switch.receive(value, now_ms=now, trusted_rearm=rearm)

    def test_restart_is_tripped_and_valid_rearm_then_heartbeat_keeps_armed(self) -> None:
        self.assertEqual(self.switch.state, "tripped")
        self.assertEqual(self.send(action="rearm", rearm=True), "armed")
        self.assertEqual(self.send(now=NOW + 100), "armed")

    def test_heartbeat_never_implicitly_rearms(self) -> None:
        self.assertEqual(self.send(), "tripped")
        with self.assertRaises(HardwareFailSafeError):
            self.send(action="rearm", rearm=False)
        self.assertEqual(self.switch.state, "tripped")

    def test_missing_delayed_and_serial_disconnect_trip_on_timeout(self) -> None:
        self.send(action="rearm", rearm=True)
        self.assertEqual(self.switch.tick(NOW + 999), "armed")
        self.assertEqual(self.switch.tick(NOW + 1_000), "tripped")
        self.assertEqual(self.switch.trip_reason, "heartbeat-timeout")

    def test_replay_reorder_and_stale_sequence_trip(self) -> None:
        self.send(action="rearm", rearm=True)
        challenge = self.switch.issue_challenge(NOW + 10)
        message = self.client.respond(
            challenge, now_ms=NOW + 10, policy_version="policy-v1",
            evidence_chain_digest=self.evidence,
        )
        self.switch.receive(message, now_ms=NOW + 10)
        replay_challenge = self.switch.issue_challenge(NOW + 20)
        replay = copy.deepcopy(message.to_dict())
        replay["claims"]["challenge_id"] = replay_challenge.challenge_id
        replay["claims"]["challenge_nonce"] = replay_challenge.nonce
        with self.assertRaises(HardwareFailSafeError):
            self.switch.receive(replay, now_ms=NOW + 20)
        self.assertEqual(self.switch.state, "tripped")

    def test_forged_malformed_policy_and_evidence_fail_closed(self) -> None:
        cases = (
            {"signature": "A" * 86},
            {"policy": "policy-v2"},
            {"evidence": "f" * 64},
            {"device_id": "other-switch"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.setUp()
                if "signature" in changes:
                    challenge = self.switch.issue_challenge(NOW)
                    value = self.client.respond(
                        challenge, now_ms=NOW, policy_version="policy-v1",
                        evidence_chain_digest=self.evidence,
                    ).to_dict()
                    value["signature"] = changes["signature"]
                    with self.assertRaises(HardwareFailSafeError):
                        self.switch.receive(value, now_ms=NOW)
                else:
                    with self.assertRaises(HardwareFailSafeError):
                        self.send(**changes)
                self.assertEqual(self.switch.state, "tripped")

    def test_expired_challenge_and_message_fail_closed(self) -> None:
        challenge = self.switch.issue_challenge(NOW, lifetime_ms=10)
        message = self.client.respond(
            challenge, now_ms=NOW, policy_version="policy-v1",
            evidence_chain_digest=self.evidence, lifetime_ms=10,
        )
        with self.assertRaises(HardwareFailSafeError):
            self.switch.receive(message, now_ms=NOW + 10)

    def test_explicit_kill_canary_and_behavioral_reasons_trip(self) -> None:
        for reason in ("trusted-kill", "repeated-canary", "behavioral-quarantine"):
            with self.subTest(reason=reason):
                self.setUp()
                self.send(action="rearm", rearm=True)
                self.assertEqual(self.send(action="kill", payload={"reason": reason}), "tripped")
                self.assertEqual(self.switch.trip_reason, reason)

    def test_key_rotation_rejects_old_key_and_accepts_new_key_after_rearm(self) -> None:
        self.send(action="rearm", rearm=True)
        rotated = FailSafeHostClient(
            "switch-1", b"rotated-hardware-key-no-external-authority",
            initial_sequence=self.client.sequence,
        )
        self.send(action="rotate-key", payload={
            "new_key_id": rotated.key_id,
            "new_public_key_pem": rotated.public_key_pem,
        })
        with self.assertRaises(HardwareFailSafeError):
            self.send(client=self.client)
        self.assertEqual(self.switch.state, "tripped")
        rotated = FailSafeHostClient(
            "switch-1", b"rotated-hardware-key-no-external-authority",
            initial_sequence=self.switch.last_sequence,
        )
        self.assertEqual(self.send(action="rearm", rearm=True, client=rotated), "armed")

    def test_host_restart_without_sequence_continuity_trips(self) -> None:
        self.send(action="rearm", rearm=True)
        self.send(now=NOW + 10)
        restarted = FailSafeHostClient("switch-1", b"hardware-simulator-test-key-no-authority")
        with self.assertRaises(HardwareFailSafeError):
            self.send(now=NOW + 20, client=restarted)

    def test_failure_while_tripped_never_restores_connectivity(self) -> None:
        with self.assertRaises(HardwareFailSafeError):
            self.send(evidence="f" * 64)
        self.assertEqual(self.switch.tick(NOW + 10_000), "tripped")


if __name__ == "__main__":
    unittest.main()
