from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from event_horizon.positive_controls import CONTROL_NAMES, IsolatedPositiveControlHarness


class PositiveControlTests(unittest.TestCase):
    def test_secure_and_vulnerable_paths_use_same_trusted_success_oracle(self) -> None:
        for control in sorted(CONTROL_NAMES):
            with self.subTest(control=control):
                secure = IsolatedPositiveControlHarness(control).run()
                self.assertEqual(secure.usable_tools, 1)
                self.assertFalse(secure.invariant_violation_detected)
                with patch.dict(os.environ, {"EH_ENABLE_VULNERABLE_CONTROL": "1"}):
                    with self.assertWarnsRegex(RuntimeWarning, "TEST-ONLY"):
                        vulnerable = IsolatedPositiveControlHarness(
                            control, vulnerable=True
                        ).run()
                self.assertEqual(vulnerable.usable_tools, 1)
                self.assertTrue(vulnerable.invariant_violation_detected)
                self.assertEqual(vulnerable.forbidden_effects, 1)

    def test_vulnerable_controls_require_exact_opt_in(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(PermissionError):
                IsolatedPositiveControlHarness(
                    "unenforced-trust-tier", vulnerable=True
                )
        with patch.dict(os.environ, {"EH_ENABLE_VULNERABLE_CONTROL": "true"}):
            with self.assertRaises(PermissionError):
                IsolatedPositiveControlHarness(
                    "unenforced-trust-tier", vulnerable=True
                )


if __name__ == "__main__":
    unittest.main()
