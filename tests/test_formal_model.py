from __future__ import annotations

import unittest

from scripts.check_formal_model import INVARIANTS, structural_check


class FormalModelStructureTests(unittest.TestCase):
    def test_model_declares_all_required_invariants_and_broken_mutation(self) -> None:
        structural_check()
        self.assertEqual(len(INVARIANTS), 20)


if __name__ == "__main__":
    unittest.main()
