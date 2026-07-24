# Firecracker development target

## Security properties

`firecracker/config.template.json` and the generated per-run configuration contain two drives (read-only rootfs and ephemeral scratch), one vsock device, no network interface, and no MMDS configuration. The guest has no package manager, shell, host mount, or credential injection. Its one static PID-1 agent mounts only proc/sys/dev/scratch and accepts canonical length-prefixed `root_probe` and `shutdown` messages.

The external watchdog receives exact paths inside a newly created run directory. It stops the VM, truncates and deletes scratch/configuration, removes the vsock socket, and writes hash-protected teardown evidence. Hardware isolation is claimed only if that evidence is complete.

## Build the minimal rootfs

Run on Linux as an unprivileged user with a static-capable `gcc` and `mkfs.ext4` available:

```bash
./scripts/build-firecracker-rootfs.sh
```

The script creates `firecracker/build/rootfs.ext4` and `SHA256SUMS`. The filesystem contains only the static PID-1 agent and empty mount points, so it has no package manager or shell. Supply a compatible uncompressed Linux kernel separately.

## Run with KVM

```bash
export EH_FIRECRACKER_BIN=/usr/local/bin/firecracker
export EH_FIRECRACKER_KERNEL=/absolute/path/to/vmlinux
export EH_FIRECRACKER_ROOTFS="$PWD/firecracker/event-horizon-rootfs.ext4"
python scripts/run_firecracker_demo.py
```

The runner uses Firecracker's `--no-api --config-file` mode so there is no general HTTP API in the trusted runtime path. A successful run writes `run-evidence.json` containing kernel/rootfs/configuration digests, the deliberate UID-0 probe, zero authority findings, route-less egress evidence, and watchdog teardown evidence. Use `--evidence-output /separately-administered/path/run-evidence.json` to atomically persist a copy outside an ephemeral runtime filesystem.

WSL2's `/mnt/c` does not support the Unix socket semantics Firecracker needs for vsock. Use a native Linux runtime directory and an external evidence copy:

```bash
python scripts/run_firecracker_demo.py \
  --workdir /tmp/event-horizon-firecracker-runs \
  --evidence-output "$PWD/.demo/firecracker-run-evidence.json"
```

`firecracker/fixtures/wsl2-nested-kvm-run.json` records the successful 2026-07-24 development run: Firecracker 1.15.1 on nested WSL2 KVM, UID 0, no credentials/package manager/network/MMDS, clean guest reboot, and complete watchdog destruction. It is development evidence, not a production jailer claim.

## KVM-unavailable fallback

The default is denial (exit code 3). For development only:

```bash
python scripts/run_firecracker_demo.py --fallback process
```

This creates `ISOLATION_MODE.json` with `hardware_isolation_claimed: false`. It exercises authority containment but makes no VM-isolation claim.
