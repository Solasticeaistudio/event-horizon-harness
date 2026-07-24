from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import time
from pathlib import Path


def inside(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f'watchdog target escaped run directory: {resolved}') from exc
    return resolved


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def invalidate_and_unlink(path: Path) -> bool:
    if not path.exists():
        return True
    if not path.is_file():
        raise ValueError(f'refusing to destroy non-file target: {path}')
    descriptor = os.open(path, os.O_WRONLY)
    try:
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.unlink()
    return not path.exists()


def main() -> int:
    parser = argparse.ArgumentParser(description='External Firecracker teardown watchdog')
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--vsock', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--deadline-seconds', type=float, default=30.0)
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    scratch = inside(args.scratch, run_dir)
    vsock = inside(args.vsock, run_dir)
    config = inside(args.config, run_dir)
    evidence_path = inside(args.evidence, run_dir)
    started_at = time.time()
    deadline = started_at + args.deadline_seconds
    forced = False
    while process_alive(args.pid) and time.time() < deadline:
        time.sleep(0.05)
    if process_alive(args.pid):
        os.kill(args.pid, signal.SIGKILL)
        forced = True
        for _ in range(100):
            if not process_alive(args.pid):
                break
            time.sleep(0.02)

    scratch_destroyed = invalidate_and_unlink(scratch)
    config_destroyed = invalidate_and_unlink(config)
    if vsock.exists():
        if not vsock.is_socket():
            raise ValueError('refusing to remove non-socket vsock path')
        vsock.unlink()

    evidence = {
        'config_destroyed': config_destroyed,
        'deadline_seconds': args.deadline_seconds,
        'finished_at': time.time(),
        'forced_termination': forced,
        'process_stopped': not process_alive(args.pid),
        'scratch_destroyed': scratch_destroyed,
        'started_at': started_at,
        'vm_pid': args.pid,
        'vsock_removed': not vsock.exists(),
    }
    encoded = json.dumps(evidence, sort_keys=True, separators=(',', ':')).encode('utf-8')
    envelope = {
        'evidence': evidence,
        'sha256': hashlib.sha256(encoded).hexdigest(),
    }
    evidence_path.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding='utf-8')
    return 0 if all((scratch_destroyed, config_destroyed, evidence['process_stopped'], evidence['vsock_removed'])) else 1


if __name__ == '__main__':
    raise SystemExit(main())
