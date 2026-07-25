import json
import unittest
from pathlib import Path

from event_horizon.experiment import (
    ExperimentComparison,
    ExperimentRecord,
    ExperimentValidationError,
    build_scripted_reference_comparison,
)


FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "experiments" / "scripted-reference-comparison.json"


class ExperimentFormatTests(unittest.TestCase):
    def test_fixed_comparison_is_reproducible_and_explicitly_synthetic(self):
        fixture = ExperimentComparison.from_json(FIXTURE.read_bytes())
        generated = build_scripted_reference_comparison()
        self.assertEqual(fixture.to_dict(), generated.to_dict())
        self.assertFalse(fixture.real_campaign_result)
        self.assertEqual(fixture.result_source, "scripted-synthetic")
        self.assertIsNone(fixture.event_horizon.certificate_signature)
        self.assertEqual(fixture.event_horizon.evidence_chain_verification, "not-measured")

    def test_pairing_and_mode_invariants_fail_closed(self):
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
        payload["event_horizon"]["seed"] = 5
        with self.assertRaisesRegex(ExperimentValidationError, "not paired"):
            ExperimentComparison.from_dict(payload)
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
        payload["baseline"]["attestation_digest"] = "0" * 64
        with self.assertRaisesRegex(ExperimentValidationError, "must not claim"):
            ExperimentComparison.from_dict(payload)
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
        payload["event_horizon"]["attestation_digest"] = None
        with self.assertRaisesRegex(ExperimentValidationError, "requires"):
            ExperimentComparison.from_dict(payload)

    def test_unknown_fields_bad_counts_and_reversed_time_are_rejected(self):
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))["baseline"]
        payload["unexpected"] = True
        with self.assertRaisesRegex(ExperimentValidationError, "fields"):
            ExperimentRecord.from_dict(payload)
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))["baseline"]
        payload["unauthorized_egress_bytes"] = -1
        with self.assertRaisesRegex(ExperimentValidationError, "non-negative"):
            ExperimentRecord.from_dict(payload)
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))["baseline"]
        payload["end_time"] = "2025-12-31T23:59:59Z"
        with self.assertRaisesRegex(ExperimentValidationError, "precedes"):
            ExperimentRecord.from_dict(payload)

    def test_duplicate_keys_and_real_campaign_mislabel_are_rejected(self):
        raw = FIXTURE.read_text(encoding="utf-8")
        duplicate = raw.replace(
            '"schema": "event-horizon.experiment-comparison.v1",',
            '"schema": "event-horizon.experiment-comparison.v1",\n  "schema": "event-horizon.experiment-comparison.v1",',
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate"):
            ExperimentComparison.from_json(duplicate)
        payload = json.loads(raw)
        payload["real_campaign_result"] = True
        with self.assertRaisesRegex(ExperimentValidationError, "scripted synthetic"):
            ExperimentComparison.from_dict(payload)


if __name__ == "__main__":
    unittest.main()
