from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from event_horizon.certificate import ContainmentCertificateBuilder
from event_horizon.component_ids import EXECUTOR_ATTESTATION_GUARDIAN
from event_horizon.factory import build_local_harness


class ExecutorAttestationIntegrationTests(unittest.TestCase):
    def test_guardian_records_verified_attestation_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            neural, _executor, recorder, _broker = build_local_harness(tmp)
            neural.request_capability({
                "request_id": "att-1",
                "session_id": "att-session",
                "agent_id": "attacker-agent",
                "operation": "object.read",
                "resource_id": "target-source",
                "executor_id": "exec-1",
                "arguments": {"offset": 0, "length": 10},
                "purpose": "attestation test",
            })
            decisions = [
                event for event in recorder.events()
                if event["event_type"] == "guardian.decision"
                and event["payload"].get("guardian") == EXECUTOR_ATTESTATION_GUARDIAN
            ]
            self.assertEqual(len(decisions), 1)
            evidence = decisions[0]["payload"]["evidence"]
            self.assertEqual(evidence["method"], "simulator")
            self.assertEqual(evidence["trust_level"], "simulated")
            self.assertTrue(evidence["bundle_digest"])
            self.assertTrue(evidence["measurement"])

    def test_certificate_is_ed25519_signed_and_binds_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            neural, executor, recorder, _broker = build_local_harness(tmp)
            request, capability = neural.request_capability({
                "request_id": "cert-1",
                "session_id": "cert-session",
                "agent_id": "attacker-agent",
                "operation": "object.read",
                "resource_id": "target-source",
                "executor_id": "exec-1",
                "arguments": {"offset": 0, "length": 10},
                "purpose": "certificate test",
            })
            executor.execute(request, capability)
            certificate = ContainmentCertificateBuilder(recorder, b"C" * 32).build(
                run_id="cert-run",
                session_id="cert-session",
                assertions={"contained": True},
            )
            self.assertEqual(certificate["algorithm"], "Ed25519")
            self.assertTrue(certificate["certificate"]["attestation_bundle_digests"])
            self.assertTrue(ContainmentCertificateBuilder.verify(certificate))
            certificate["certificate"]["completed_actions"] = 999
            self.assertFalse(ContainmentCertificateBuilder.verify(certificate))


if __name__ == "__main__":
    unittest.main()
