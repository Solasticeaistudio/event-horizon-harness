from __future__ import annotations

import queue
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .canonical import canonical_bytes, digest, strict_json_loads
from .component_ids import BEHAVIORAL_TRANSITION_GUARDIAN
from .models import ActionRequest, GuardianDecision, ValidationError
from .task_policy import AuthorityReduction


BEHAVIORAL_MODES = frozenset({"rule", "anomaly", "shadow", "evaluation"})
SECURITY_SIGNALS = frozenset({
    "canary-interaction", "capability-id-guessing", "nonce-guessing",
    "stale-attestation", "consumed-capability", "parser-probing",
    "evidence-suppression", "scope-expansion", "trust-escalation",
})


class BehavioralStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class BehavioralSessionState:
    tenant: str
    session_id: str
    request_count: int = 0
    denial_count: int = 0
    risk_score: int = 0
    first_seen_ms: int = 0
    last_seen_ms: int = 0
    last_outcome: str = "none"
    last_request: Mapping[str, Any] | None = None
    workloads: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    workers: tuple[str, ...] = ()
    signals: tuple[str, ...] = ()
    quarantined: bool = False

    FIELDS = frozenset({
        "tenant", "session_id", "request_count", "denial_count", "risk_score",
        "first_seen_ms", "last_seen_ms", "last_outcome", "last_request", "workloads",
        "resources", "workers", "signals", "quarantined",
    })

    def __post_init__(self) -> None:
        if not self.tenant or not self.session_id:
            raise ValidationError("behavioral state identity is invalid")
        for name in (
            "request_count", "denial_count", "risk_score", "first_seen_ms", "last_seen_ms",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValidationError("behavioral state counters must be non-negative integers")
        if self.last_outcome not in {"none", "allowed", "denied", "timeout", "indeterminate"}:
            raise ValidationError("behavioral state outcome is invalid")
        if self.last_request is not None:
            ActionRequest.from_dict(self.last_request)
        for name in ("workloads", "resources", "workers", "signals"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or len(values) > 256 or len(set(values)) != len(values):
                raise ValidationError("behavioral state collection is invalid")
        if set(self.signals) - SECURITY_SIGNALS:
            raise ValidationError("behavioral state contains an unknown signal")
        if type(self.quarantined) is not bool:
            raise ValidationError("behavioral quarantine flag is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant,
            "session_id": self.session_id,
            "request_count": self.request_count,
            "denial_count": self.denial_count,
            "risk_score": self.risk_score,
            "first_seen_ms": self.first_seen_ms,
            "last_seen_ms": self.last_seen_ms,
            "last_outcome": self.last_outcome,
            "last_request": dict(self.last_request) if self.last_request is not None else None,
            "workloads": list(self.workloads),
            "resources": list(self.resources),
            "workers": list(self.workers),
            "signals": list(self.signals),
            "quarantined": self.quarantined,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BehavioralSessionState":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ValidationError("behavioral state fields are invalid")
        payload = dict(value)
        for name in ("workloads", "resources", "workers", "signals"):
            payload[name] = tuple(payload[name])
        return cls(**payload)


StateTransition = Callable[[BehavioralSessionState], BehavioralSessionState]


class BehavioralStateStore(Protocol):
    def update(self, tenant: str, session_id: str, transition: StateTransition) -> BehavioralSessionState: ...
    def load(self, tenant: str, session_id: str) -> BehavioralSessionState: ...


class InMemoryBehavioralStateStore:
    def __init__(self):
        self._states: dict[tuple[str, str], BehavioralSessionState] = {}
        self._lock = threading.RLock()

    def load(self, tenant: str, session_id: str) -> BehavioralSessionState:
        with self._lock:
            return self._states.get(
                (tenant, session_id), BehavioralSessionState(tenant, session_id)
            )

    def update(self, tenant: str, session_id: str, transition: StateTransition) -> BehavioralSessionState:
        with self._lock:
            current = self.load(tenant, session_id)
            updated = transition(current)
            if updated.tenant != tenant or updated.session_id != session_id:
                raise BehavioralStateError("behavioral transition changed state ownership")
            self._states[(tenant, session_id)] = updated
            return updated


class SqliteBehavioralStateStore:
    """Single-database atomic state store for restart and worker continuity."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS behavioral_state ("
            "tenant TEXT NOT NULL, session_id TEXT NOT NULL, payload BLOB NOT NULL, "
            "payload_digest TEXT NOT NULL, PRIMARY KEY (tenant, session_id))"
        )
        self._connection.commit()

    def _load_locked(self, tenant: str, session_id: str) -> BehavioralSessionState:
        row = self._connection.execute(
            "SELECT payload, payload_digest FROM behavioral_state WHERE tenant=? AND session_id=?",
            (tenant, session_id),
        ).fetchone()
        if row is None:
            return BehavioralSessionState(tenant, session_id)
        try:
            payload = bytes(row[0])
            value = strict_json_loads(payload, require_canonical=True)
            if digest(value) != row[1]:
                raise BehavioralStateError("behavioral state digest mismatch")
            state = BehavioralSessionState.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise BehavioralStateError("behavioral state is corrupt") from exc
        if state.tenant != tenant or state.session_id != session_id:
            raise BehavioralStateError("behavioral state ownership mismatch")
        return state

    def load(self, tenant: str, session_id: str) -> BehavioralSessionState:
        with self._lock:
            return self._load_locked(tenant, session_id)

    def update(self, tenant: str, session_id: str, transition: StateTransition) -> BehavioralSessionState:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                current = self._load_locked(tenant, session_id)
                updated = transition(current)
                if updated.tenant != tenant or updated.session_id != session_id:
                    raise BehavioralStateError("behavioral transition changed state ownership")
                payload = canonical_bytes(updated.to_dict())
                self._connection.execute(
                    "INSERT INTO behavioral_state VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(tenant, session_id) DO UPDATE SET "
                    "payload=excluded.payload, payload_digest=excluded.payload_digest",
                    (tenant, session_id, payload, digest(updated.to_dict())),
                )
                self._connection.commit()
                return updated
            except Exception:
                self._connection.rollback()
                raise

    def close(self) -> None:
        self._connection.close()


class BehavioralModel(Protocol):
    version: str
    def score(self, state: BehavioralSessionState, request: ActionRequest) -> Mapping[str, Any]: ...


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key == "request_id":
                continue
            result.update(_flatten(item, f"{prefix}.{key}" if prefix else key))
        return result
    if isinstance(value, (list, tuple)):
        result = {}
        for index, item in enumerate(value):
            result.update(_flatten(item, f"{prefix}[{index}]"))
        return result
    return {prefix: value}


def _one_field_changed(previous: Mapping[str, Any] | None, current: Mapping[str, Any]) -> bool:
    if previous is None:
        return False
    left = _flatten(previous)
    right = _flatten(current)
    keys = set(left) | set(right)
    return sum(left.get(key) != right.get(key) for key in keys) == 1


@dataclass
class BehavioralGuardian:
    store: BehavioralStateStore
    tenant: str = "default"
    mode: str = "rule"
    model: BehavioralModel | None = None
    model_timeout_seconds: float = 1.0
    reduction_threshold: int = 60
    quarantine_threshold: int = 100
    slow_probe_window_ms: int = 60_000
    name: str = BEHAVIORAL_TRANSITION_GUARDIAN

    def __post_init__(self) -> None:
        if self.mode not in BEHAVIORAL_MODES:
            raise ValueError("behavioral guardian mode is invalid")
        if not 0 < self.model_timeout_seconds <= 30:
            raise ValueError("behavioral model timeout is invalid")
        if not 0 < self.reduction_threshold <= self.quarantine_threshold:
            raise ValueError("behavioral thresholds are invalid")

    def _model_output(
        self, state: BehavioralSessionState, request: ActionRequest
    ) -> tuple[int, AuthorityReduction | None, str | None]:
        if self.model is None:
            return 0, None, "behavioral model unavailable"
        output: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

        def invoke() -> None:
            try:
                output.put((True, self.model.score(state, request)), block=False)
            except Exception as exc:
                output.put((False, exc), block=False)

        worker = threading.Thread(target=invoke, daemon=True, name="behavioral-model")
        worker.start()
        worker.join(self.model_timeout_seconds)
        if worker.is_alive():
            return 0, None, "behavioral model timed out"
        try:
            ok, value = output.get_nowait()
        except queue.Empty:
            return 0, None, "behavioral model returned no result"
        if not ok or not isinstance(value, Mapping) or set(value) != {"risk_delta", "reduction"}:
            return 0, None, "behavioral model output is malformed"
        risk_delta = value["risk_delta"]
        if type(risk_delta) is not int or not 0 <= risk_delta <= 100:
            return 0, None, "behavioral model risk is malformed"
        try:
            reduction = (
                AuthorityReduction.from_dict(value["reduction"])
                if value["reduction"] is not None
                else None
            )
        except (TypeError, ValueError):
            return 0, None, "behavioral model attempted a non-subtractive response"
        return risk_delta, reduction, None

    def evaluate_context(
        self,
        request: ActionRequest,
        *,
        now_ms: int,
        worker_id: str = "local",
    ) -> GuardianDecision:
        decision: dict[str, Any] = {}

        def transition(state: BehavioralSessionState) -> BehavioralSessionState:
            signals: list[str] = []
            risk_delta = 0
            payload = request.canonical_payload()
            if _one_field_changed(state.last_request, payload):
                signals.append("one-field-mutation")
                risk_delta += 35
            resources = tuple(sorted({*state.resources, request.resource_id}))
            workloads = tuple(sorted({*state.workloads, request.executor_id}))
            workers = tuple(sorted({*state.workers, worker_id}))
            if len(resources) >= 3 and len(resources) > len(state.resources):
                signals.append("resource-enumeration")
                risk_delta += 35
            if len(workloads) > 1:
                signals.append("workload-mutation")
                risk_delta += 100
            if state.denial_count >= 2:
                signals.append("repeated-denials")
                risk_delta += 30
            if state.last_outcome == "denied" and now_ms - state.last_seen_ms <= 1_000:
                signals.append("rapid-retry-after-denial")
                risk_delta += 25
            first_seen = state.first_seen_ms or now_ms
            if state.request_count >= 4 and now_ms - first_seen >= self.slow_probe_window_ms:
                signals.append("slow-probing")
                risk_delta += 35
            if len(workers) > 1 and (risk_delta or state.denial_count):
                signals.append("distributed-probing")
                risk_delta += 25
            model_reduction = None
            model_error = None
            model_delta = 0
            if self.mode in {"anomaly", "shadow", "evaluation"}:
                model_delta, model_reduction, model_error = self._model_output(state, request)
                if self.mode == "anomaly" and model_error is not None:
                    decision.update({"model_error": model_error, "model_failure": True})
                elif self.mode == "anomaly":
                    risk_delta += model_delta
            risk_score = min(1_000, state.risk_score + risk_delta)
            quarantined = state.quarantined or risk_score >= self.quarantine_threshold
            decision.update({
                "signals": signals,
                "risk_score": risk_score,
                "model_error": model_error,
                "model_delta": model_delta,
                "model_reduction": model_reduction,
                "quarantined": quarantined,
            })
            return BehavioralSessionState(
                tenant=state.tenant,
                session_id=state.session_id,
                request_count=state.request_count + 1,
                denial_count=state.denial_count,
                risk_score=risk_score,
                first_seen_ms=first_seen,
                last_seen_ms=now_ms,
                last_outcome=state.last_outcome,
                last_request=payload,
                workloads=workloads,
                resources=resources,
                workers=workers,
                signals=state.signals,
                quarantined=quarantined,
            )

        try:
            state = self.store.update(self.tenant, request.session_id, transition)
        except Exception:
            return GuardianDecision(
                self.name, False, "behavioral guardian state unavailable",
                {"authority_reduction": AuthorityReduction(
                    source=self.name, revoke=True, require_human_approval=True
                ).to_dict()},
                request.request_digest,
            )
        if decision.get("model_failure"):
            return GuardianDecision(
                self.name, False, str(decision["model_error"]),
                {"authority_reduction": AuthorityReduction(
                    source=self.name, require_human_approval=True
                ).to_dict()},
                request.request_digest,
            )
        reduction = (
            decision.get("model_reduction")
            if self.mode == "anomaly" and isinstance(decision.get("model_reduction"), AuthorityReduction)
            else None
        )
        if state.quarantined:
            reduction = AuthorityReduction(
                source=self.name,
                maximum_calls=0,
                maximum_read_bytes=0,
                maximum_write_bytes=0,
                revoke=True,
                require_human_approval=True,
            )
        elif state.risk_score >= self.reduction_threshold:
            reduction = AuthorityReduction(
                source=self.name,
                maximum_calls=1,
                maximum_parallelism=1,
                maximum_write_bytes=0,
                require_reattestation=True,
            )
        evidence: dict[str, Any] = {
            "risk_score": state.risk_score,
            "signals": decision.get("signals", []),
            "state_digest": digest(state.to_dict()),
            "mode": self.mode,
        }
        if reduction is not None:
            evidence["authority_reduction"] = reduction.to_dict()
        if self.mode in {"shadow", "evaluation"}:
            model_reduction = decision.get("model_reduction")
            evidence["shadow_reduction"] = (
                model_reduction.to_dict() if isinstance(model_reduction, AuthorityReduction) else None
            )
            evidence["model_error"] = decision.get("model_error")
        allowed = not state.quarantined
        reason = "boundary-probing threshold exceeded" if not allowed else (
            "behavioral authority reduction required" if reduction else "no boundary-probing pattern detected"
        )
        return GuardianDecision(self.name, allowed, reason, evidence, request.request_digest)

    def evaluate(self, request: ActionRequest) -> GuardianDecision:
        return self.evaluate_context(request, now_ms=time.time_ns() // 1_000_000)

    def record_outcome(
        self,
        request: ActionRequest,
        outcome: str,
        *,
        now_ms: int,
    ) -> BehavioralSessionState:
        if outcome not in {"allowed", "denied", "timeout", "indeterminate"}:
            raise ValueError("behavioral outcome is invalid")

        def transition(state: BehavioralSessionState) -> BehavioralSessionState:
            values = state.to_dict()
            values["last_outcome"] = outcome
            values["last_seen_ms"] = max(state.last_seen_ms, now_ms)
            if outcome == "denied":
                values["denial_count"] = state.denial_count + 1
            return BehavioralSessionState.from_dict(values)

        return self.store.update(self.tenant, request.session_id, transition)

    def record_security_signal(
        self,
        session_id: str,
        signal: str,
        *,
        now_ms: int,
    ) -> BehavioralSessionState:
        if signal not in SECURITY_SIGNALS:
            raise ValueError("behavioral security signal is invalid")

        def transition(state: BehavioralSessionState) -> BehavioralSessionState:
            values = state.to_dict()
            values["signals"] = sorted({*state.signals, signal})
            values["risk_score"] = min(1_000, state.risk_score + (
                100 if signal == "canary-interaction" else 40
            ))
            values["quarantined"] = values["risk_score"] >= self.quarantine_threshold
            values["last_seen_ms"] = max(state.last_seen_ms, now_ms)
            return BehavioralSessionState.from_dict(values)

        return self.store.update(self.tenant, session_id, transition)

    def recover(
        self,
        session_id: str,
        *,
        trusted_reattestation: bool = False,
        human_approved: bool = False,
    ) -> BehavioralSessionState:
        if not trusted_reattestation and not human_approved:
            raise PermissionError("behavioral recovery requires a new trusted authorization event")

        def transition(state: BehavioralSessionState) -> BehavioralSessionState:
            return BehavioralSessionState(
                tenant=state.tenant,
                session_id=state.session_id,
                first_seen_ms=state.first_seen_ms,
                last_seen_ms=state.last_seen_ms,
            )

        return self.store.update(self.tenant, session_id, transition)


def behavioral_evaluation_report(labels: list[bool], detections: list[bool]) -> dict[str, int]:
    if len(labels) != len(detections) or not labels:
        raise ValueError("behavioral evaluation requires paired non-empty labels")
    positives = sum(labels)
    negatives = len(labels) - positives
    true_positive = sum(expected and actual for expected, actual in zip(labels, detections))
    false_positive = sum(not expected and actual for expected, actual in zip(labels, detections))
    return {
        "samples": len(labels),
        "detection_rate_millis": 0 if not positives else true_positive * 1000 // positives,
        "false_positive_rate_millis": 0 if not negatives else false_positive * 1000 // negatives,
    }
