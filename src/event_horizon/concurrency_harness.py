from __future__ import annotations

import os
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .broker import CapabilityError, CapabilityVerifier
from .models import ActionRequest, IssuedCapability
from .replay_state import CapabilityConsumptionError, CapabilityConsumptionStore


class ResponseDropped(RuntimeError):
    pass


@dataclass(frozen=True)
class ConcurrentRedemptionResult:
    attempts: int
    accepted_redemptions: int
    committed_effects: int
    replay_denials: int
    partition_denials: int
    indeterminate_responses: int
    distinct_idempotency_keys: int
    invariant_passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


class ConcurrentRedemptionHarness:
    """Deterministic thread stress for one exact capability and one effect counter."""

    def __init__(
        self,
        verifier_factories: Sequence[Callable[[], CapabilityVerifier]],
        *,
        attempts: int = 512,
    ):
        if not verifier_factories or attempts < 100 or attempts > 10_000:
            raise ValueError("concurrency harness requires 100..10000 attempts and verifiers")
        self.verifier_factories = tuple(verifier_factories)
        self.attempts = attempts

    def run(
        self,
        capability: IssuedCapability,
        request: ActionRequest,
        context: Mapping[str, Any],
        *,
        now: float,
        storage_latency_seconds: float = 0.0001,
        executor_latency_seconds: float = 0.0001,
        recorder_latency_seconds: float = 0.0001,
        partition_attempts: frozenset[int] = frozenset(),
        dropped_response_attempts: frozenset[int] = frozenset(),
    ) -> ConcurrentRedemptionResult:
        if any(index < 0 or index >= self.attempts for index in partition_attempts):
            raise ValueError("partition attempt index is outside the campaign")
        lock = threading.Lock()
        barrier = threading.Barrier(self.attempts)
        committed = 0
        accepted = 0
        replay_denials = 0
        partition_denials = 0
        indeterminate = 0
        idempotency_keys: set[str] = set()

        def attempt(index: int) -> None:
            nonlocal committed, accepted, replay_denials, partition_denials, indeterminate
            verifier = self.verifier_factories[index % len(self.verifier_factories)]()
            idempotency_key = f"attempt-{index}"
            barrier.wait()
            if storage_latency_seconds:
                time.sleep(storage_latency_seconds * (index % 3))
            if index in partition_attempts:
                with lock:
                    partition_denials += 1
                    idempotency_keys.add(idempotency_key)
                return
            try:
                verifier.verify_and_consume(
                    capability, request, **dict(context), now=now
                )
                if executor_latency_seconds:
                    time.sleep(executor_latency_seconds * (index % 2))
                with lock:
                    accepted += 1
                    committed += 1
                    idempotency_keys.add(idempotency_key)
                if recorder_latency_seconds:
                    time.sleep(recorder_latency_seconds)
                if index in dropped_response_attempts:
                    raise ResponseDropped("response dropped after committed effect")
            except ResponseDropped:
                with lock:
                    indeterminate += 1
            except CapabilityError:
                with lock:
                    replay_denials += 1
                    idempotency_keys.add(idempotency_key)

        with ThreadPoolExecutor(max_workers=self.attempts) as pool:
            list(pool.map(attempt, range(self.attempts)))
        return ConcurrentRedemptionResult(
            attempts=self.attempts,
            accepted_redemptions=accepted,
            committed_effects=committed,
            replay_denials=replay_denials,
            partition_denials=partition_denials,
            indeterminate_responses=indeterminate,
            distinct_idempotency_keys=len(idempotency_keys),
            invariant_passed=committed <= 1,
        )


class VulnerableNonAtomicConsumptionStore(CapabilityConsumptionStore):
    """Test-only positive control. Never instantiate outside an explicitly gated test."""

    def __init__(self, competitors: int):
        if os.environ.get("EH_ENABLE_VULNERABLE_CONTROL") != "1":
            raise PermissionError(
                "vulnerable control disabled; set EH_ENABLE_VULNERABLE_CONTROL=1 only in tests"
            )
        if competitors < 2 or competitors > 1_000:
            raise ValueError("vulnerable control competitor count is invalid")
        warnings.warn(
            "DANGER: TEST-ONLY NON-ATOMIC REDEMPTION CONTROL ENABLED",
            RuntimeWarning,
            stacklevel=2,
        )
        self._values: dict[str, tuple[str, int]] = {}
        self._barrier = threading.Barrier(competitors)

    def consume(
        self,
        capability_id: str,
        claims_digest: str,
        expires_at: int,
        consumed_at: int,
    ) -> bool:
        if not capability_id.startswith("cap_") or len(claims_digest) != 64:
            raise CapabilityConsumptionError("vulnerable control received malformed input")
        previous = self._values.get(capability_id)
        if previous is not None:
            return False
        self._barrier.wait(timeout=10)
        self._values[capability_id] = (claims_digest, expires_at)
        return True


def sqlite_verifier_factories(
    database: str | Path,
    public_key_pem: str,
    key_id: str,
    *,
    replicas: int = 8,
) -> tuple[Callable[[], CapabilityVerifier], ...]:
    from .replay_state import SqliteCapabilityConsumptionStore

    stores = tuple(
        SqliteCapabilityConsumptionStore(
            database,
            namespace="concurrency-harness",
            domain="effect-executor",
        )
        for _ in range(replicas)
    )
    return tuple(
        lambda store=store: CapabilityVerifier(public_key_pem, key_id, store)
        for store in stores
    )
