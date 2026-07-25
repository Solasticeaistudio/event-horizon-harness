from __future__ import annotations

import sqlite3
import threading
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from .canonical import canonical_bytes, digest, strict_json_loads
from .models import ActionRequest, ValidationError
from .task_policy import CompiledTaskPolicyCeiling


DECAY_TRIGGERS = frozenset({
    "elapsed_ms", "use_count", "read_bytes", "write_bytes", "denials", "risk_score",
    "canary_events", "trust_age_ms", "policy_age_ms", "environment_changes",
    "workload_restarts",
})
REFRESH_REQUIREMENTS = ("fresh-attestation", "fresh-authorization")


class DecayError(PermissionError):
    pass


def _nonnegative(value: Any, name: str) -> int:
    if type(value) is not int or value < 0 or value > 2**53 - 1:
        raise ValidationError(f"{name} must be a non-negative bounded integer")
    return value


def _strings(value: Sequence[Any], name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > 256:
        raise ValidationError(f"{name} must be a bounded array")
    result = tuple(sorted(value))
    if any(not isinstance(item, str) or not item for item in result) or len(set(result)) != len(result):
        raise ValidationError(f"{name} items must be unique non-empty strings")
    return result


@dataclass(frozen=True)
class DecayAuthority:
    expires_at_ms: int
    remaining_calls: int
    remaining_read_bytes: int
    remaining_write_bytes: int
    network_destinations: tuple[str, ...]
    tools: tuple[str, ...]
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    argument_ranges: Mapping[str, tuple[int, int]]
    maximum_parallelism: int
    maximum_effect_severity: int

    FIELDS = frozenset({
        "expires_at_ms", "remaining_calls", "remaining_read_bytes", "remaining_write_bytes",
        "network_destinations", "tools", "actions", "resources", "argument_ranges",
        "maximum_parallelism", "maximum_effect_severity",
    })

    def __post_init__(self) -> None:
        for name in (
            "expires_at_ms", "remaining_calls", "remaining_read_bytes", "remaining_write_bytes",
            "maximum_parallelism", "maximum_effect_severity",
        ):
            _nonnegative(getattr(self, name), name)
        if self.maximum_effect_severity > 10:
            raise ValidationError("effect severity must be between zero and ten")
        for name in ("network_destinations", "tools", "actions", "resources"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        if not isinstance(self.argument_ranges, Mapping) or len(self.argument_ranges) > 256:
            raise ValidationError("argument ranges must be a bounded object")
        ranges: dict[str, tuple[int, int]] = {}
        for key, bounds in self.argument_ranges.items():
            if not isinstance(key, str) or not key or not isinstance(bounds, (list, tuple)) or len(bounds) != 2:
                raise ValidationError("argument range is malformed")
            low, high = bounds
            if type(low) is not int or type(high) is not int or low > high:
                raise ValidationError("argument range bounds are invalid")
            ranges[key] = (low, high)
        object.__setattr__(self, "argument_ranges", dict(sorted(ranges.items())))

    def to_dict(self) -> dict[str, Any]:
        return {
            "expires_at_ms": self.expires_at_ms,
            "remaining_calls": self.remaining_calls,
            "remaining_read_bytes": self.remaining_read_bytes,
            "remaining_write_bytes": self.remaining_write_bytes,
            "network_destinations": list(self.network_destinations),
            "tools": list(self.tools),
            "actions": list(self.actions),
            "resources": list(self.resources),
            "argument_ranges": {key: list(value) for key, value in self.argument_ranges.items()},
            "maximum_parallelism": self.maximum_parallelism,
            "maximum_effect_severity": self.maximum_effect_severity,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DecayAuthority":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ValidationError("decay authority fields are invalid")
        payload = dict(value)
        for name in ("network_destinations", "tools", "actions", "resources"):
            payload[name] = tuple(payload[name])
        payload["argument_ranges"] = {
            key: tuple(bounds) for key, bounds in payload["argument_ranges"].items()
        }
        return cls(**payload)

    @property
    def authority_digest(self) -> str:
        return digest(self.to_dict())

    def is_subset_of(self, prior: "DecayAuthority") -> bool:
        if any((
            self.expires_at_ms > prior.expires_at_ms,
            self.remaining_calls > prior.remaining_calls,
            self.remaining_read_bytes > prior.remaining_read_bytes,
            self.remaining_write_bytes > prior.remaining_write_bytes,
            self.maximum_parallelism > prior.maximum_parallelism,
            self.maximum_effect_severity > prior.maximum_effect_severity,
        )):
            return False
        for name in ("network_destinations", "tools", "actions", "resources"):
            if not set(getattr(self, name)).issubset(getattr(prior, name)):
                return False
        if set(self.argument_ranges) - set(prior.argument_ranges):
            return False
        for key, (low, high) in self.argument_ranges.items():
            prior_low, prior_high = prior.argument_ranges[key]
            if low < prior_low or high > prior_high:
                return False
        return True

    def permits(self, request: ActionRequest, now_ms: int) -> bool:
        if now_ms >= self.expires_at_ms or self.remaining_calls < 1:
            return False
        if request.operation not in self.actions or request.resource_id not in self.resources:
            return False
        for key, (low, high) in self.argument_ranges.items():
            if key in request.arguments:
                value = request.arguments[key]
                if type(value) is not int or not low <= value <= high:
                    return False
        return True


@dataclass(frozen=True)
class DecayStep:
    trigger: str
    threshold: int
    remove_network_destinations: tuple[str, ...] = ()
    remove_tools: tuple[str, ...] = ()
    remove_actions: tuple[str, ...] = ()
    remove_resources: tuple[str, ...] = ()
    maximum_calls: int | None = None
    maximum_read_bytes: int | None = None
    maximum_write_bytes: int | None = None
    maximum_parallelism: int | None = None
    maximum_effect_severity: int | None = None
    shorten_expiration_to_ms: int | None = None

    FIELDS = frozenset({
        "trigger", "threshold", "remove_network_destinations", "remove_tools",
        "remove_actions", "remove_resources", "maximum_calls", "maximum_read_bytes",
        "maximum_write_bytes", "maximum_parallelism", "maximum_effect_severity",
        "shorten_expiration_to_ms",
    })

    def __post_init__(self) -> None:
        if self.trigger not in DECAY_TRIGGERS:
            raise ValidationError("decay trigger is invalid")
        _nonnegative(self.threshold, "decay threshold")
        for name in (
            "remove_network_destinations", "remove_tools", "remove_actions", "remove_resources",
        ):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        for name in (
            "maximum_calls", "maximum_read_bytes", "maximum_write_bytes",
            "maximum_parallelism", "maximum_effect_severity", "shorten_expiration_to_ms",
        ):
            value = getattr(self, name)
            if value is not None:
                _nonnegative(value, name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trigger": self.trigger,
            "threshold": self.threshold,
            "remove_network_destinations": list(self.remove_network_destinations),
            "remove_tools": list(self.remove_tools),
            "remove_actions": list(self.remove_actions),
            "remove_resources": list(self.remove_resources),
            "maximum_calls": self.maximum_calls,
            "maximum_read_bytes": self.maximum_read_bytes,
            "maximum_write_bytes": self.maximum_write_bytes,
            "maximum_parallelism": self.maximum_parallelism,
            "maximum_effect_severity": self.maximum_effect_severity,
            "shorten_expiration_to_ms": self.shorten_expiration_to_ms,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DecayStep":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ValidationError("decay step fields are invalid")
        payload = dict(value)
        for name in (
            "remove_network_destinations", "remove_tools", "remove_actions", "remove_resources",
        ):
            payload[name] = tuple(payload[name])
        return cls(**payload)


@dataclass(frozen=True)
class DecayProfile:
    profile_id: str
    version: str
    initial_authority: DecayAuthority
    steps: tuple[DecayStep, ...]
    refresh_requirements: tuple[str, ...] = REFRESH_REQUIREMENTS

    FIELDS = frozenset({
        "profile_id", "version", "initial_authority", "steps", "refresh_requirements"
    })

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, str) or not self.profile_id:
            raise ValidationError("decay profile ID is invalid")
        if not isinstance(self.version, str) or not self.version:
            raise ValidationError("decay profile version is invalid")
        if not isinstance(self.initial_authority, DecayAuthority):
            raise ValidationError("decay profile initial authority is invalid")
        if not isinstance(self.steps, tuple) or any(not isinstance(step, DecayStep) for step in self.steps):
            raise ValidationError("decay profile steps are invalid")
        object.__setattr__(
            self, "steps", tuple(sorted(self.steps, key=lambda item: (item.trigger, item.threshold)))
        )
        object.__setattr__(
            self, "refresh_requirements", _strings(self.refresh_requirements, "refresh requirements")
        )
        if self.refresh_requirements != tuple(sorted(REFRESH_REQUIREMENTS)):
            raise ValidationError("decay refresh requires fresh attestation and authorization")

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "version": self.version,
            "initial_authority": self.initial_authority.to_dict(),
            "steps": [step.to_dict() for step in self.steps],
            "refresh_requirements": list(self.refresh_requirements),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DecayProfile":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ValidationError("decay profile fields are invalid")
        return cls(
            profile_id=value["profile_id"],
            version=value["version"],
            initial_authority=DecayAuthority.from_dict(value["initial_authority"]),
            steps=tuple(DecayStep.from_dict(step) for step in value["steps"]),
            refresh_requirements=tuple(value["refresh_requirements"]),
        )

    @property
    def profile_digest(self) -> str:
        return digest(self.to_dict())


def decay_profile_for_ceiling(
    ceiling: CompiledTaskPolicyCeiling,
    *,
    version: str = "v1",
    issued_at_ms: int | None = None,
    expires_at_ms: int | None = None,
) -> DecayProfile:
    effective_issued_at = ceiling.issued_at_ms if issued_at_ms is None else issued_at_ms
    effective_expires_at = ceiling.expires_at_ms if expires_at_ms is None else expires_at_ms
    _nonnegative(effective_issued_at, "decay issuance time")
    _nonnegative(effective_expires_at, "decay expiration time")
    if effective_expires_at <= effective_issued_at:
        raise ValidationError("decay expiration must follow issuance")
    if effective_expires_at > ceiling.expires_at_ms:
        raise ValidationError("decay expiration cannot exceed the compiled ceiling")
    initial = DecayAuthority(
        expires_at_ms=effective_expires_at,
        remaining_calls=min(1, ceiling.maximum_calls),
        remaining_read_bytes=ceiling.maximum_read_bytes,
        remaining_write_bytes=ceiling.maximum_write_bytes,
        network_destinations=ceiling.network_destinations,
        tools=ceiling.tools,
        actions=ceiling.actions,
        resources=tuple(sorted({item for values in ceiling.action_resources.values() for item in values})),
        argument_ranges={},
        maximum_parallelism=ceiling.maximum_parallelism,
        maximum_effect_severity=10,
    )
    steps: tuple[DecayStep, ...] = ()
    if ceiling.decay_profile != "none":
        midpoint = max(1, (effective_expires_at - effective_issued_at) // 2)
        steps = (
            DecayStep(
                "elapsed_ms", midpoint,
                remove_network_destinations=ceiling.network_destinations,
                maximum_write_bytes=0,
                maximum_parallelism=1,
                maximum_effect_severity=5,
            ),
            DecayStep(
                "canary_events", 1,
                maximum_calls=0,
                maximum_read_bytes=0,
                maximum_write_bytes=0,
                maximum_parallelism=0,
                maximum_effect_severity=0,
            ),
        )
    return DecayProfile(ceiling.decay_profile, version, initial, steps)


@dataclass(frozen=True)
class DecayState:
    capability_id: str
    profile_digest: str
    max_observed_time_ms: int
    use_count: int
    read_bytes: int
    write_bytes: int
    denials: int
    risk_score: int
    canary_events: int
    trust_age_ms: int
    policy_age_ms: int
    environment_changes: int
    workload_restarts: int
    current_authority: DecayAuthority

    FIELDS = frozenset({
        "capability_id", "profile_digest", "max_observed_time_ms", "use_count",
        "read_bytes", "write_bytes", "denials", "risk_score", "canary_events",
        "trust_age_ms", "policy_age_ms", "environment_changes", "workload_restarts",
        "current_authority",
    })

    def __post_init__(self) -> None:
        if not isinstance(self.capability_id, str) or not self.capability_id:
            raise ValidationError("decay state capability ID is invalid")
        if not isinstance(self.profile_digest, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.profile_digest
        ):
            raise ValidationError("decay state profile digest is invalid")
        for name in self.FIELDS - {"capability_id", "profile_digest", "current_authority"}:
            _nonnegative(getattr(self, name), name)
        if not isinstance(self.current_authority, DecayAuthority):
            raise ValidationError("decay state authority is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "profile_digest": self.profile_digest,
            "max_observed_time_ms": self.max_observed_time_ms,
            "use_count": self.use_count,
            "read_bytes": self.read_bytes,
            "write_bytes": self.write_bytes,
            "denials": self.denials,
            "risk_score": self.risk_score,
            "canary_events": self.canary_events,
            "trust_age_ms": self.trust_age_ms,
            "policy_age_ms": self.policy_age_ms,
            "environment_changes": self.environment_changes,
            "workload_restarts": self.workload_restarts,
            "current_authority": self.current_authority.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DecayState":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ValidationError("decay state fields are invalid")
        payload = dict(value)
        for name in cls.FIELDS - {"capability_id", "profile_digest", "current_authority"}:
            _nonnegative(payload[name], name)
        payload["current_authority"] = DecayAuthority.from_dict(payload["current_authority"])
        return cls(**payload)

    @property
    def state_digest(self) -> str:
        return digest(self.to_dict())


DecayTransition = Callable[[DecayState | None], DecayState]


def _validate_state_transition(
    capability_id: str,
    prior: DecayState | None,
    state: DecayState,
) -> None:
    if state.capability_id != capability_id:
        raise DecayError("decay transition changed capability identity")
    if prior is None:
        return
    if state.profile_digest != prior.profile_digest:
        raise DecayError("decay transition changed the profile")
    for name in (
        "max_observed_time_ms", "use_count", "read_bytes", "write_bytes", "denials",
        "risk_score", "canary_events", "trust_age_ms", "policy_age_ms",
        "environment_changes", "workload_restarts",
    ):
        if getattr(state, name) < getattr(prior, name):
            raise DecayError(f"decay transition reduced monotonic counter: {name}")
    if not state.current_authority.is_subset_of(prior.current_authority):
        raise DecayError("decay transition attempted to increase authority")


class DecayStateStore(Protocol):
    def update(self, capability_id: str, transition: DecayTransition) -> DecayState: ...
    def load(self, capability_id: str) -> DecayState | None: ...


class InMemoryDecayStateStore:
    def __init__(self):
        self._states: dict[str, DecayState] = {}
        self._lock = threading.RLock()

    def load(self, capability_id: str) -> DecayState | None:
        with self._lock:
            return self._states.get(capability_id)

    def update(self, capability_id: str, transition: DecayTransition) -> DecayState:
        with self._lock:
            prior = self._states.get(capability_id)
            state = transition(prior)
            _validate_state_transition(capability_id, prior, state)
            self._states[capability_id] = state
            return state


class SqliteDecayStateStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS decay_state (capability_id TEXT PRIMARY KEY, "
            "payload BLOB NOT NULL, payload_digest TEXT NOT NULL)"
        )
        self._connection.commit()

    def _load_locked(self, capability_id: str) -> DecayState | None:
        row = self._connection.execute(
            "SELECT payload, payload_digest FROM decay_state WHERE capability_id=?",
            (capability_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            value = strict_json_loads(bytes(row[0]), require_canonical=True)
            if digest(value) != row[1]:
                raise DecayError("decay state digest mismatch")
            state = DecayState.from_dict(value)
        except (TypeError, ValueError) as exc:
            raise DecayError("decay state is corrupt") from exc
        if state.capability_id != capability_id:
            raise DecayError("decay state capability mismatch")
        return state

    def load(self, capability_id: str) -> DecayState | None:
        with self._lock:
            return self._load_locked(capability_id)

    def update(self, capability_id: str, transition: DecayTransition) -> DecayState:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                prior = self._load_locked(capability_id)
                state = transition(prior)
                _validate_state_transition(capability_id, prior, state)
                payload = canonical_bytes(state.to_dict())
                self._connection.execute(
                    "INSERT INTO decay_state VALUES (?, ?, ?) ON CONFLICT(capability_id) "
                    "DO UPDATE SET payload=excluded.payload, payload_digest=excluded.payload_digest",
                    (capability_id, payload, digest(state.to_dict())),
                )
                self._connection.commit()
                return state
            except Exception:
                self._connection.rollback()
                raise

    def close(self) -> None:
        self._connection.close()


def _apply_step(authority: DecayAuthority, step: DecayStep, issued_at_ms: int) -> DecayAuthority:
    expiration = authority.expires_at_ms
    if step.shorten_expiration_to_ms is not None:
        expiration = min(expiration, issued_at_ms + step.shorten_expiration_to_ms)
    return DecayAuthority(
        expires_at_ms=expiration,
        remaining_calls=min(authority.remaining_calls, step.maximum_calls) if step.maximum_calls is not None else authority.remaining_calls,
        remaining_read_bytes=min(authority.remaining_read_bytes, step.maximum_read_bytes) if step.maximum_read_bytes is not None else authority.remaining_read_bytes,
        remaining_write_bytes=min(authority.remaining_write_bytes, step.maximum_write_bytes) if step.maximum_write_bytes is not None else authority.remaining_write_bytes,
        network_destinations=tuple(item for item in authority.network_destinations if item not in step.remove_network_destinations),
        tools=tuple(item for item in authority.tools if item not in step.remove_tools),
        actions=tuple(item for item in authority.actions if item not in step.remove_actions),
        resources=tuple(item for item in authority.resources if item not in step.remove_resources),
        argument_ranges=authority.argument_ranges,
        maximum_parallelism=min(authority.maximum_parallelism, step.maximum_parallelism) if step.maximum_parallelism is not None else authority.maximum_parallelism,
        maximum_effect_severity=min(authority.maximum_effect_severity, step.maximum_effect_severity) if step.maximum_effect_severity is not None else authority.maximum_effect_severity,
    )


@dataclass(frozen=True)
class DecayEvaluation:
    authorized_authority: DecayAuthority
    resulting_state: DecayState
    clock_rollback_observed: bool


class DecayEngine:
    def __init__(self, store: DecayStateStore | None = None):
        self.store = store or InMemoryDecayStateStore()

    def authorize(
        self,
        capability_id: str,
        profile: DecayProfile,
        request: ActionRequest,
        *,
        issued_at_ms: int,
        now_ms: int,
        read_bytes: int = 0,
        write_bytes: int = 0,
        denials: int = 0,
        risk_score: int = 0,
        canary_events: int = 0,
        trust_age_ms: int = 0,
        policy_age_ms: int = 0,
        environment_changes: int = 0,
        workload_restarts: int = 0,
    ) -> DecayEvaluation:
        for name, value in locals().copy().items():
            if name in {
                "read_bytes", "write_bytes", "denials", "risk_score", "canary_events",
                "trust_age_ms", "policy_age_ms", "environment_changes", "workload_restarts",
            }:
                _nonnegative(value, name)
        if now_ms < issued_at_ms - 5_000:
            raise DecayError("decay clock is before capability issuance")
        outcome: dict[str, Any] = {}

        def transition(prior: DecayState | None) -> DecayState:
            if prior is not None and prior.profile_digest != profile.profile_digest:
                raise DecayError("decay profile substitution detected")
            effective_now = max(now_ms, prior.max_observed_time_ms if prior else now_ms)
            rollback = prior is not None and now_ms < prior.max_observed_time_ms
            prior_counters = {
                "elapsed_ms": max(0, effective_now - issued_at_ms),
                "use_count": prior.use_count if prior else 0,
                "read_bytes": (prior.read_bytes if prior else 0) + read_bytes,
                "write_bytes": (prior.write_bytes if prior else 0) + write_bytes,
                "denials": (prior.denials if prior else 0) + denials,
                "risk_score": max(prior.risk_score if prior else 0, risk_score),
                "canary_events": (prior.canary_events if prior else 0) + canary_events,
                "trust_age_ms": max(prior.trust_age_ms if prior else 0, trust_age_ms),
                "policy_age_ms": max(prior.policy_age_ms if prior else 0, policy_age_ms),
                "environment_changes": (prior.environment_changes if prior else 0) + environment_changes,
                "workload_restarts": (prior.workload_restarts if prior else 0) + workload_restarts,
            }
            authorized = prior.current_authority if prior is not None else profile.initial_authority
            for step in profile.steps:
                if prior_counters[step.trigger] >= step.threshold:
                    authorized = _apply_step(authorized, step, issued_at_ms)
            if prior is not None and not authorized.is_subset_of(prior.current_authority):
                raise DecayError("decay transition attempted to increase authority")
            if not authorized.permits(request, effective_now):
                raise DecayError("current decay authority denies the request")

            counters = dict(prior_counters)
            counters["use_count"] += 1
            current = authorized
            for step in profile.steps:
                if counters[step.trigger] >= step.threshold:
                    current = _apply_step(current, step, issued_at_ms)
            current = DecayAuthority(
                **{
                    **current.to_dict(),
                    "network_destinations": current.network_destinations,
                    "tools": current.tools,
                    "actions": current.actions,
                    "resources": current.resources,
                    "argument_ranges": current.argument_ranges,
                    "remaining_calls": min(
                        current.remaining_calls,
                        max(0, profile.initial_authority.remaining_calls - counters["use_count"]),
                    ),
                    "remaining_read_bytes": min(
                        current.remaining_read_bytes,
                        max(0, profile.initial_authority.remaining_read_bytes - counters["read_bytes"]),
                    ),
                    "remaining_write_bytes": min(
                        current.remaining_write_bytes,
                        max(0, profile.initial_authority.remaining_write_bytes - counters["write_bytes"]),
                    ),
                }
            )
            if not current.is_subset_of(authorized):
                raise DecayError("decay transition attempted to increase authority")
            state = DecayState(
                capability_id=capability_id,
                profile_digest=profile.profile_digest,
                max_observed_time_ms=effective_now,
                use_count=counters["use_count"],
                read_bytes=counters["read_bytes"],
                write_bytes=counters["write_bytes"],
                denials=counters["denials"],
                risk_score=counters["risk_score"],
                canary_events=counters["canary_events"],
                trust_age_ms=counters["trust_age_ms"],
                policy_age_ms=counters["policy_age_ms"],
                environment_changes=counters["environment_changes"],
                workload_restarts=counters["workload_restarts"],
                current_authority=current,
            )
            outcome.update({"authorized": authorized, "state": state, "rollback": rollback})
            return state

        try:
            resulting = self.store.update(capability_id, transition)
        except DecayError:
            raise
        except Exception as exc:
            raise DecayError("decay state unavailable") from exc
        return DecayEvaluation(outcome["authorized"], resulting, outcome["rollback"])

    def refresh(
        self,
        old_capability_id: str,
        new_capability_id: str,
        new_profile: DecayProfile,
        *,
        fresh_attestation_digest: str,
        fresh_authorization_digest: str,
    ) -> DecayState:
        if old_capability_id == new_capability_id:
            raise DecayError("refresh cannot reuse a capability ID")
        for value in (fresh_attestation_digest, fresh_authorization_digest):
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise DecayError("refresh requires fresh attestation and authorization digests")

        def transition(prior: DecayState | None) -> DecayState:
            if prior is not None:
                raise DecayError("stale refresh response cannot replace existing authority")
            return DecayState(
                capability_id=new_capability_id,
                profile_digest=new_profile.profile_digest,
                max_observed_time_ms=0,
                use_count=0,
                read_bytes=0,
                write_bytes=0,
                denials=0,
                risk_score=0,
                canary_events=0,
                trust_age_ms=0,
                policy_age_ms=0,
                environment_changes=0,
                workload_restarts=0,
                current_authority=new_profile.initial_authority,
            )

        return self.store.update(new_capability_id, transition)
