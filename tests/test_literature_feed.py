from __future__ import annotations

import copy
import unittest
from pathlib import Path

from event_horizon.literature_feed import LiteratureFeedError, SandboxEscapeBenchAdapter


FIXTURE = Path(__file__).resolve().parents[1] / "literature-fixtures" / "sandbox-escape-bench.json"


class LiteratureFeedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = SandboxEscapeBenchAdapter()
        self.fixture = self.adapter.load(FIXTURE)
        first = self.fixture.techniques[0]
        self.observed = {
            "source_version": first.source_version,
            "source_digest": first.source_digest,
            "license": first.license,
            "technique_ids": [item.technique_id for item in self.fixture.techniques],
        }

    def test_pinned_fixture_is_metadata_only_and_awaits_human_review(self) -> None:
        self.assertEqual(len(self.fixture.techniques), 6)
        self.assertTrue(all(item.review_status == "pending-human-review" for item in self.fixture.techniques))
        self.assertTrue(all("execute" not in item.safe_simulation_method.lower() for item in self.fixture.techniques))

    def test_offline_drift_report_is_deterministic(self) -> None:
        report = self.adapter.drift_report(self.fixture, self.observed)
        self.assertFalse(report.source_hash_changed)
        self.assertEqual(report.new_techniques, ())
        self.assertEqual(len(report.campaigns_requiring_review), 6)

    def test_version_license_new_and_removed_drift_are_reported(self) -> None:
        observed = copy.deepcopy(self.observed)
        observed.update({
            "source_version": "f" * 40,
            "source_digest": "f" * 64,
            "license": "changed-license",
            "technique_ids": observed["technique_ids"][1:] + ["seb/new-technique"],
        })
        report = self.adapter.drift_report(self.fixture, observed)
        self.assertTrue(report.source_hash_changed)
        self.assertEqual(report.new_techniques, ("seb/new-technique",))
        self.assertEqual(report.removed_techniques, (self.observed["technique_ids"][0],))
        self.assertEqual(report.license_changes, ("changed-license",))

    def test_unknown_or_unsafe_fixture_fields_fail_closed(self) -> None:
        value = self.fixture.techniques[0].to_dict()
        value["unknown"] = True
        with self.assertRaises(LiteratureFeedError):
            type(self.fixture.techniques[0]).from_dict(value)
        value.pop("unknown")
        value["safe_simulation_method"] = "download and execute exploit code"
        with self.assertRaises(LiteratureFeedError):
            type(self.fixture.techniques[0]).from_dict(value)


if __name__ == "__main__":
    unittest.main()
