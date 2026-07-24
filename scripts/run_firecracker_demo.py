from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VSOCK_PORT = 5000
MAX_FRAME = 4096


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def write_durable_json(path: Path, value: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.tmp-{os.getpid()}')
    encoded = json.dumps(value, indent=2, sort_keys=True).encode('utf-8')
    with temporary.open('xb') as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def exact_child(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    resolved.relative_to(root.resolve())
    return resolved


def read_exact(channel: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = channel.recv(remaining)
        if not chunk:
            raise EOFError('vsock channel closed')
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def send_frame(channel: socket.socket, message: dict[str, Any]) -> dict[str, Any]:
    payload = json.dumps(message, sort_keys=True, separators=(',', ':')).encode('utf-8')
    if not payload or len(payload) > MAX_FRAME:
        raise ValueError('vsock request exceeded fixed envelope')
    channel.sendall(struct.pack('>I', len(payload)) + payload)
    size = struct.unpack('>I', read_exact(channel, 4))[0]
    if size == 0 or size > MAX_FRAME:
        raise ValueError('vsock response exceeded fixed envelope')
    encoded = read_exact(channel, size)
    response = json.loads(encoded)
    if json.dumps(response, sort_keys=True, separators=(',', ':')).encode('utf-8') != encoded:
        raise ValueError('guest response was not canonical JSON')
    if not isinstance(response, dict):
        raise ValueError('guest response was not an object')
    return response


def connect_vsock(path: Path, deadline: float) -> socket.socket:
    while time.time() < deadline:
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        channel.settimeout(2.0)
        try:
            channel.connect(str(path))
            channel.sendall(f'CONNECT {VSOCK_PORT}\n'.encode('ascii'))
            acknowledgement = bytearray()
            while not acknowledgement.endswith(b'\n') and len(acknowledgement) < 64:
                byte = channel.recv(1)
                if not byte:
                    raise ConnectionError('Firecracker closed the vsock control connection')
                acknowledgement.extend(byte)
            if not acknowledgement.startswith(b'OK '):
                raise ConnectionError('Firecracker rejected vsock connection')
            return channel
        except (FileNotFoundError, ConnectionError, ConnectionRefusedError, socket.timeout):
            channel.close()
            time.sleep(0.05)
    raise TimeoutError('guest vsock agent did not become ready')


def kvm_available(firecracker: str | None) -> bool:
    return bool(
        sys.platform.startswith('linux')
        and firecracker
        and os.path.exists('/dev/kvm')
        and os.access('/dev/kvm', os.R_OK | os.W_OK)
    )


def run_process_fallback(workdir: Path) -> int:
    sys.path.insert(0, str(REPOSITORY_ROOT / 'src'))
    from event_horizon.process_demo import main as process_demo

    fallback_dir = workdir / 'process-fallback'
    fallback_dir.mkdir(parents=True, exist_ok=True)
    marker = {
        'hardware_isolation_claimed': False,
        'isolation_mode': 'process-fallback',
        'reason': 'KVM or Firecracker unavailable',
    }
    (fallback_dir / 'ISOLATION_MODE.json').write_text(
        json.dumps(marker, indent=2, sort_keys=True),
        encoding='utf-8',
    )
    print('KVM unavailable: running explicitly labeled process fallback')
    return process_demo(['--workdir', str(fallback_dir)])


def run_firecracker(
    *,
    firecracker: str,
    kernel: Path,
    rootfs: Path,
    workdir: Path,
    timeout_seconds: float,
    evidence_output: Path | None = None,
) -> int:
    for name, path in (('kernel', kernel), ('rootfs', rootfs)):
        if not path.is_file():
            raise FileNotFoundError(f'{name} image does not exist: {path}')
    workdir.mkdir(parents=True, exist_ok=True)
    run_dir = exact_child(workdir / f'run-{int(time.time())}-{os.getpid()}', workdir)
    run_dir.mkdir(mode=0o700)
    scratch = exact_child(run_dir / 'scratch.ext4', run_dir)
    vsock = exact_child(run_dir / 'vsock.sock', run_dir)
    config_path = exact_child(run_dir / 'firecracker.json', run_dir)
    watchdog_evidence = exact_child(run_dir / 'watchdog-evidence.json', run_dir)
    run_evidence_path = exact_child(run_dir / 'run-evidence.json', run_dir)
    console_path = exact_child(run_dir / 'console.log', run_dir)

    with scratch.open('xb') as handle:
        handle.truncate(64 * 1024 * 1024)
        handle.flush()
        os.fsync(handle.fileno())
    subprocess.run(['mkfs.ext4', '-q', '-F', '-L', 'EH_SCRATCH', str(scratch)], check=True)
    config = {
        'boot-source': {
            'kernel_image_path': str(kernel.resolve()),
            'boot_args': 'console=ttyS0 reboot=k panic=1 pci=off random.trust_cpu=on init=/init',
        },
        'drives': [
            {
                'drive_id': 'rootfs',
                'path_on_host': str(rootfs.resolve()),
                'is_root_device': True,
                'is_read_only': True,
            },
            {
                'drive_id': 'scratch',
                'path_on_host': str(scratch),
                'is_root_device': False,
                'is_read_only': False,
            },
        ],
        'machine-config': {
            'vcpu_count': 1,
            'mem_size_mib': 128,
            'smt': False,
            'track_dirty_pages': False,
        },
        'vsock': {'guest_cid': 52, 'uds_path': str(vsock)},
    }
    if 'network-interfaces' in config or 'mmds-config' in config:
        raise ValueError('network or metadata configuration is forbidden')
    encoded_config = json.dumps(config, sort_keys=True, separators=(',', ':')).encode('utf-8')
    config_path.write_bytes(encoded_config)
    config_digest = hashlib.sha256(encoded_config).hexdigest()

    safe_environment = {'PATH': os.environ.get('PATH', '/usr/sbin:/usr/bin:/sbin:/bin')}
    console = console_path.open('wb')
    vm = subprocess.Popen(
        [firecracker, '--no-api', '--config-file', str(config_path)],
        cwd=run_dir,
        env=safe_environment,
        stdin=subprocess.DEVNULL,
        stdout=console,
        stderr=subprocess.STDOUT,
    )
    watchdog = subprocess.Popen(
        [
            sys.executable,
            str(REPOSITORY_ROOT / 'scripts' / 'firecracker_watchdog.py'),
            '--pid', str(vm.pid),
            '--run-dir', str(run_dir),
            '--scratch', str(scratch),
            '--vsock', str(vsock),
            '--config', str(config_path),
            '--evidence', str(watchdog_evidence),
            '--deadline-seconds', str(timeout_seconds),
        ],
        cwd=REPOSITORY_ROOT,
        env=safe_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    root_probe: dict[str, Any] | None = None
    try:
        with connect_vsock(vsock, time.time() + min(timeout_seconds, 15.0)) as channel:
            root_probe = send_frame(channel, {'type': 'root_probe'})
            if set(root_probe) != {'authority_environment', 'authority_files', 'package_manager', 'uid'}:
                raise ValueError('guest root probe fields are invalid')
            if root_probe != {
                'authority_environment': 0,
                'authority_files': 0,
                'package_manager': False,
                'uid': 0,
            }:
                raise RuntimeError(f'guest root exposed authority: {root_probe}')
            shutdown = send_frame(channel, {'type': 'shutdown'})
            if shutdown != {'accepted': True}:
                raise RuntimeError('guest rejected deterministic shutdown')
        vm.wait(timeout=10)
    finally:
        if vm.poll() is None:
            vm.terminate()
            try:
                vm.wait(timeout=2)
            except subprocess.TimeoutExpired:
                vm.kill()
                vm.wait(timeout=2)
        console.close()
        watchdog.wait(timeout=timeout_seconds + 5)

    watchdog_envelope = json.loads(watchdog_evidence.read_text(encoding='utf-8'))
    teardown = watchdog_envelope['evidence']
    if not all((teardown['process_stopped'], teardown['scratch_destroyed'], teardown['config_destroyed'], teardown['vsock_removed'])):
        raise RuntimeError('watchdog teardown evidence is incomplete')
    evidence = {
        'configuration_digest': config_digest,
        'egress': {
            'metadata_configured': False,
            'network_interfaces': 0,
            'unrestricted_connectors': 0,
        },
        'hardware_isolation_claimed': True,
        'isolation_mode': 'firecracker-kvm',
        'kernel_sha256': sha256_file(kernel),
        'root_probe': root_probe,
        'rootfs_read_only': True,
        'rootfs_sha256': sha256_file(rootfs),
        'teardown': teardown,
        'vsock_protocol': 'fixed-length-prefixed-v1',
    }
    write_durable_json(run_evidence_path, evidence)
    if evidence_output is not None:
        write_durable_json(evidence_output, evidence)
    print(json.dumps(evidence, indent=2, sort_keys=True))
    print(f'run evidence: {run_evidence_path}')
    if evidence_output is not None:
        print(f'external evidence copy: {evidence_output.resolve()}')
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Run the route-less Event Horizon Firecracker target')
    parser.add_argument('--firecracker', default=os.environ.get('EH_FIRECRACKER_BIN', 'firecracker'))
    parser.add_argument('--kernel', type=Path, default=os.environ.get('EH_FIRECRACKER_KERNEL'))
    parser.add_argument('--rootfs', type=Path, default=os.environ.get('EH_FIRECRACKER_ROOTFS'))
    parser.add_argument('--workdir', type=Path, default=REPOSITORY_ROOT / '.demo' / 'firecracker')
    parser.add_argument('--timeout-seconds', type=float, default=30.0)
    parser.add_argument('--evidence-output', type=Path)
    parser.add_argument('--fallback', choices=('deny', 'process'), default='deny')
    args = parser.parse_args(argv)
    executable = shutil.which(args.firecracker)
    assets_available = args.kernel is not None and args.rootfs is not None
    if not kvm_available(executable) or not assets_available:
        if args.fallback == 'process':
            return run_process_fallback(args.workdir)
        print('Firecracker denied: Linux KVM, firecracker, kernel, and rootfs are all required', file=sys.stderr)
        print('Use --fallback process only for an explicitly non-hardware development run', file=sys.stderr)
        return 3
    return run_firecracker(
        firecracker=executable,
        kernel=args.kernel,
        rootfs=args.rootfs,
        workdir=args.workdir,
        timeout_seconds=args.timeout_seconds,
        evidence_output=args.evidence_output,
    )


if __name__ == '__main__':
    raise SystemExit(main())
