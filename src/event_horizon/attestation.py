from __future__ import annotations

import json
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol


class AttestationError(RuntimeError):
    pass


class AttestationProvider(Protocol):
    def verify_executor(self, executor_id: str) -> Mapping[str, Any]: ...


@dataclass
class StaticAttestationProvider:
    """Explicit development fallback for tests that do not run HardProof."""

    measurements: Mapping[str, str]

    def verify_executor(self, executor_id: str) -> Mapping[str, Any]:
        measurement = self.measurements.get(executor_id)
        if not measurement:
            raise AttestationError("executor has no trusted measurement")
        return {
            "valid": True,
            "deviceId": executor_id,
            "method": "static-development",
            "trustLevel": "software",
            "assuranceLevel": "development",
            "measurements": {"executor": measurement},
            "bundleDigest": "static-development-evidence",
        }


@dataclass
class HardProofDevelopmentProvider:
    """Runs the rebuilt HardProof verifier outside the hostile executor.

    This provider is intentionally a development bridge. The production trusted
    path will use a fixed local protocol and a separately administered verifier.
    """

    hardproof_root: Path
    device_seeds: Mapping[str, str]
    node_binary: str = "node"
    timeout_seconds: float = 10.0
    _cache: dict[str, Mapping[str, Any]] = field(default_factory=dict, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)

    def verify_executor(self, executor_id: str) -> Mapping[str, Any]:
        seed = self.device_seeds.get(executor_id)
        if not seed:
            raise AttestationError("executor is not enrolled with HardProof")
        with self._lock:
            cached = self._cache.get(executor_id)
            if cached:
                return cached
            script = self.hardproof_root / "bridge" / "verify-executor.mjs"
            if not script.exists():
                raise AttestationError(f"HardProof bridge missing: {script}")
            try:
                completed = subprocess.run(
                    [self.node_binary, str(script), executor_id, seed],
                    cwd=self.hardproof_root,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise AttestationError(f"HardProof verifier unavailable: {exc}") from exc
            if completed.returncode != 0:
                detail = completed.stderr.strip() or completed.stdout.strip() or "unknown verifier failure"
                raise AttestationError(f"HardProof verification failed: {detail}")
            try:
                result = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise AttestationError("HardProof verifier returned malformed JSON") from exc
            if not isinstance(result, dict) or not result.get("valid"):
                raise AttestationError(str(result.get("failureReason", "attestation rejected")))
            measurements = result.get("measurements")
            if not isinstance(measurements, dict) or not measurements.get("executor"):
                raise AttestationError("HardProof result omitted executor measurement")
            self._cache[executor_id] = result
            return result
