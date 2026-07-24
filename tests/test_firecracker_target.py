from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.run_firecracker_demo import kvm_available, main, write_durable_json
from scripts.firecracker_watchdog import inside, invalidate_and_unlink


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class FirecrackerTargetTests(unittest.TestCase):
    def test_external_evidence_copy_is_atomic_and_canonical(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'external' / 'run-evidence.json'
            write_durable_json(path, {'verified': True})
            self.assertEqual(json.loads(path.read_text(encoding='utf-8')), {'verified': True})
            self.assertEqual(list(path.parent.glob('.*.tmp-*')), [])

    def test_watchdog_confines_and_invalidates_exact_run_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / 'run'
            run_dir.mkdir()
            scratch = run_dir / 'scratch.ext4'
            scratch.write_bytes(b'secret scratch state')
            self.assertEqual(inside(scratch, run_dir), scratch.resolve())
            self.assertTrue(invalidate_and_unlink(scratch))
            self.assertFalse(scratch.exists())
            with self.assertRaises(ValueError):
                inside(Path(tmp) / 'outside.ext4', run_dir)

    def test_template_is_route_less_read_only_and_vsock_only(self):
        config = json.loads(
            (REPOSITORY_ROOT / 'firecracker' / 'config.template.json').read_text(encoding='utf-8')
        )
        self.assertNotIn('network-interfaces', config)
        self.assertNotIn('mmds-config', config)
        self.assertEqual(config['vsock']['guest_cid'], 52)
        drives = {drive['drive_id']: drive for drive in config['drives']}
        self.assertTrue(drives['rootfs']['is_read_only'])
        self.assertFalse(drives['scratch']['is_read_only'])

    def test_missing_kvm_denies_unless_fallback_is_explicit(self):
        self.assertFalse(kvm_available(None))
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                denied = main([
                    '--firecracker', 'definitely-not-installed-firecracker',
                    '--workdir', tmp,
                ])
            self.assertEqual(denied, 3)

    def test_explicit_fallback_is_labeled_non_hardware(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = main([
                    '--firecracker', 'definitely-not-installed-firecracker',
                    '--workdir', tmp,
                    '--fallback', 'process',
                ])
            self.assertEqual(result, 0)
            marker = json.loads(
                (Path(tmp) / 'process-fallback' / 'ISOLATION_MODE.json').read_text(encoding='utf-8')
            )
            self.assertEqual(marker['isolation_mode'], 'process-fallback')
            self.assertFalse(marker['hardware_isolation_claimed'])


if __name__ == '__main__':
    unittest.main()
