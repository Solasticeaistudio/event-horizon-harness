from __future__ import annotations

import json
import unittest
from pathlib import Path

from event_horizon.adversarial_runner import (
    ActionProposal,
    BoundedSyntheticAdversarialRunner,
    CampaignManifest,
    CampaignValidationError,
    HarmlessSyntheticAdapter,
    SAFE_ACTIONS,
)


MANIFEST_PATH = Path(__file__).resolve().parents[1] / "examples" / "synthetic-campaign" / "manifest.json"


def manifest(**overrides):
    value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    value.update(overrides)
    return CampaignManifest.from_dict(value)


class AdversarialRunnerInterfaceTests(unittest.TestCase):
    def test_harmless_script_records_every_proposal_and_observation(self):
        records = []
        runner = BoundedSyntheticAdversarialRunner(
            ["synthetic-range/public-fixture"],
            recorder=lambda event, payload: records.append((event, payload)),
        )
        result = runner.run(manifest())
        self.assertTrue(result.completed)
        self.assertFalse(result.limit_exceeded)
        self.assertEqual([proposal.action for proposal in result.proposals], list(SAFE_ACTIONS))
        self.assertEqual(len(result.observations), 5)
        self.assertEqual(len(records), 10)
        self.assertTrue(runner.replay(manifest(), result))

    def test_unknown_ranges_urls_and_ip_addresses_are_rejected(self):
        runner = BoundedSyntheticAdversarialRunner(["synthetic-range/public-fixture"])
        with self.assertRaisesRegex(CampaignValidationError, "not declared"):
            runner.run(manifest(range_id="synthetic-range/undeclared"))
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        payload["objective"]["description"] = "connect to https://example.invalid"
        with self.assertRaisesRegex(CampaignValidationError, "URL"):
            CampaignManifest.from_dict(payload)
        with self.assertRaisesRegex(CampaignValidationError, "range_id"):
            manifest(range_id="203.0.113.10")

    def test_budget_exhaustion_stops_before_additional_actions(self):
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        payload["limits"]["maximum_turns"] = 2
        result = BoundedSyntheticAdversarialRunner(
            ["synthetic-range/public-fixture"]
        ).run(CampaignManifest.from_dict(payload))
        self.assertFalse(result.completed)
        self.assertTrue(result.limit_exceeded)
        self.assertEqual(len(result.proposals), 2)

    def test_non_simulated_adapter_requires_explicit_human_approval(self):
        class ApprovalGatedAdapter(HarmlessSyntheticAdapter):
            name = "approved-adapter"
            simulated = False

        adapter = ApprovalGatedAdapter()
        runner = BoundedSyntheticAdversarialRunner(
            ["synthetic-range/public-fixture"], adapter=adapter,
        )
        with self.assertRaisesRegex(CampaignValidationError, "human approval"):
            runner.run(manifest(adapter="approved-adapter"))
        approved = BoundedSyntheticAdversarialRunner(
            ["synthetic-range/public-fixture"],
            adapter=adapter,
            human_approval=lambda _manifest, _adapter: True,
        )
        self.assertTrue(approved.run(manifest(adapter="approved-adapter")).completed)

    def test_proposals_cannot_name_public_network_destinations(self):
        with self.assertRaisesRegex(CampaignValidationError, "outside"):
            ActionProposal(
                1,
                "attempt_prohibited_network_operation",
                "synthetic-range/public-fixture",
                "example.com",
                {},
            )
        with self.assertRaisesRegex(CampaignValidationError, "URL"):
            ActionProposal(
                1,
                "attempt_prohibited_network_operation",
                "synthetic-range/public-fixture",
                "synthetic-range/public-fixture/fixture/network-policy",
                {"destination": "https://example.invalid"},
            )


if __name__ == "__main__":
    unittest.main()
