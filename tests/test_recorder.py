from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from event_horizon.recorder import ExternalRecorder


class RecorderReceiptTests(unittest.TestCase):
    def test_receipt_is_bound_to_event_source_and_registered_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            recorder = ExternalRecorder(Path(tmp) / 'events.jsonl', b'R' * 32)
            record = recorder.append('test.event', {'ok': True}, source_id='test', source_sequence=1)
            receipt = record['receipt']
            self.assertTrue(ExternalRecorder.verify_receipt(receipt, recorder.public_key_pem))

            for field, value in (
                ('event_hash', '0' * 64),
                ('source_sequence', 2),
                ('key_id', 'ed25519:' + '0' * 32),
            ):
                tampered = copy.deepcopy(receipt)
                tampered['payload'][field] = value
                self.assertFalse(ExternalRecorder.verify_receipt(tampered, recorder.public_key_pem))

            tampered_signature = copy.deepcopy(receipt)
            tampered_signature['signature'] = receipt['signature'][:-1] + '*'
            self.assertFalse(
                ExternalRecorder.verify_receipt(tampered_signature, recorder.public_key_pem)
            )

    def test_restart_recovers_chain_with_signing_key_continuity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'events.jsonl'
            first = ExternalRecorder(path, b'R' * 32)
            first.append('before.restart', {}, source_id='test', source_sequence=1)
            recovered = ExternalRecorder(path, b'R' * 32)
            self.assertEqual(recovered.key_id, first.key_id)
            self.assertEqual(recovered.count(), 1)
            recovered.append('after.restart', {}, source_id='test', source_sequence=2)
            self.assertTrue(recovered.verify()[0])
            self.assertEqual(path.stat().st_size, 2 * 16_384)


if __name__ == '__main__':
    unittest.main()
