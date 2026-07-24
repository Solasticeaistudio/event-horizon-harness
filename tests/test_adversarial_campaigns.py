from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from event_horizon.adversarial import ScriptedAdversarialCampaignRunner
from event_horizon.process_harness import ProcessSeparatedHarness


class ScriptedAdversarialCampaignTests(unittest.TestCase):
    def test_all_owned_campaigns_are_contained_without_real_connectors(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = ProcessSeparatedHarness(tmp, inject_permissive_guardian=True).start()
            try:
                runner = ScriptedAdversarialCampaignRunner(harness)
                results = runner.run_all()
                self.assertEqual(len(results), 10)
                self.assertTrue(all(result.contained for result in results))
                self.assertEqual(harness.egress_evidence['unrestricted_connectors'], 0)
                self.assertEqual(harness.egress_evidence['unauthorized_egress_attempts_succeeded'], 0)
                self.assertTrue(harness.call('recorder', 'verify', {})['valid'])
                fixtures = json.loads(
                    (Path(tmp) / 'hostile-cell' / 'synthetic-services.json').read_text(encoding='utf-8')
                )
                self.assertTrue(all(item['endpoint'].startswith('synthetic://') for item in fixtures.values()))
                self.assertTrue(all(item['credential'].startswith('EH-HONEY-') for item in fixtures.values()))
            finally:
                harness.close()


if __name__ == '__main__':
    unittest.main()
