from __future__ import annotations

import base64
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Mapping

from .canonical import MAX_SAFE_INTEGER, digest, strict_json_loads


DIGEST = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PRIVILEGE_STAGES = {
    "none",
    "synthetic-discovery",
    "synthetic-credential-use",
    "synthetic-lateral-access",
    "synthetic-persistence",
}
EVIDENCE_RESULTS = {"verified", "failed", "not-measured"}


class ExperimentValidationError(ValueError):
    pass


def _exact_fields(payload: Mapping[str, Any], expected: set[str], name: str) -> None:
    if not isinstance(payload, Mapping) or set(payload) != expected:
        raise ExperimentValidationError(f"{name} fields are invalid")


def _identifier(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", value) is None
    ):
        raise ExperimentValidationError(f"{name} is invalid")
    return value


def _digest(value: Any, name: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ExperimentValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _count(value: Any, name: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ExperimentValidationError(f"{name} must be a non-negative interoperable integer")
    return value


def _time(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise ExperimentValidationError(f"{name} must be an RFC 3339 UTC second timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ExperimentValidationError(f"{name} is not a valid timestamp") from exc


@dataclass(frozen=True)
class CertificateSignature:
    algorithm: str
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        if self.algorithm != "Ed25519":
            raise ExperimentValidationError("certificate signature algorithm is unsupported")
        _identifier(self.key_id, "certificate key_id")
        if not isinstance(self.signature, str) or re.fullmatch(r"[A-Za-z0-9_-]{86}", self.signature) is None:
            raise ExperimentValidationError("certificate signature encoding is invalid")
        try:
            decoded = base64.urlsafe_b64decode(self.signature + "==")
        except ValueError as exc:
            raise ExperimentValidationError("certificate signature encoding is invalid") from exc
        if len(decoded) != 64:
            raise ExperimentValidationError("certificate signature length is invalid")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CertificateSignature":
        _exact_fields(payload, {"algorithm", "key_id", "signature"}, "certificate signature")
        return cls(**dict(payload))


EXPERIMENT_FIELDS = {
    "schema",
    "experiment_id",
    "mode",
    "result_source",
    "range_image_digest",
    "attacker_configuration_digest",
    "policy_digest",
    "executor_measurement",
    "attestation_digest",
    "seed",
    "start_time",
    "end_time",
    "maximum_privilege_stage",
    "credentials_discovered",
    "credentials_successfully_exercised",
    "capability_replay_attempts",
    "cross_executor_attempts",
    "lateral_targets_reached",
    "unauthorized_egress_bytes",
    "persistence_after_teardown",
    "evidence_tampering_attempts",
    "evidence_chain_verification",
    "certificate_signature",
}


@dataclass(frozen=True)
class ExperimentRecord:
    schema: str
    experiment_id: str
    mode: str
    result_source: str
    range_image_digest: str
    attacker_configuration_digest: str
    policy_digest: str
    executor_measurement: str
    attestation_digest: str | None
    seed: int
    start_time: str
    end_time: str
    maximum_privilege_stage: str
    credentials_discovered: int
    credentials_successfully_exercised: int
    capability_replay_attempts: int
    cross_executor_attempts: int
    lateral_targets_reached: int
    unauthorized_egress_bytes: int
    persistence_after_teardown: bool | None
    evidence_tampering_attempts: int
    evidence_chain_verification: str
    certificate_signature: CertificateSignature | None

    def __post_init__(self) -> None:
        if self.schema != "event-horizon.experiment.v1":
            raise ExperimentValidationError("experiment schema is unsupported")
        _identifier(self.experiment_id, "experiment_id")
        if self.mode not in {"baseline", "event-horizon"}:
            raise ExperimentValidationError("experiment mode is unsupported")
        if self.result_source != "scripted-synthetic":
            raise ExperimentValidationError("public experiment result source is unsupported")
        for name in (
            "range_image_digest",
            "attacker_configuration_digest",
            "policy_digest",
            "executor_measurement",
        ):
            _digest(getattr(self, name), name)
        _digest(self.attestation_digest, "attestation_digest", optional=True)
        if self.mode == "baseline" and self.attestation_digest is not None:
            raise ExperimentValidationError("baseline mode must not claim executor attestation")
        if self.mode == "event-horizon" and self.attestation_digest is None:
            raise ExperimentValidationError("event-horizon mode requires an attestation digest")
        _count(self.seed, "seed")
        started = _time(self.start_time, "start_time")
        ended = _time(self.end_time, "end_time")
        if ended < started:
            raise ExperimentValidationError("end_time precedes start_time")
        if self.maximum_privilege_stage not in PRIVILEGE_STAGES:
            raise ExperimentValidationError("maximum_privilege_stage is unsupported")
        for name in (
            "credentials_discovered",
            "credentials_successfully_exercised",
            "capability_replay_attempts",
            "cross_executor_attempts",
            "lateral_targets_reached",
            "unauthorized_egress_bytes",
            "evidence_tampering_attempts",
        ):
            _count(getattr(self, name), name)
        if self.credentials_successfully_exercised > self.credentials_discovered:
            raise ExperimentValidationError("exercised credentials exceed discovered credentials")
        if self.persistence_after_teardown is not None and type(self.persistence_after_teardown) is not bool:
            raise ExperimentValidationError("persistence_after_teardown must be boolean or null")
        if self.evidence_chain_verification not in EVIDENCE_RESULTS:
            raise ExperimentValidationError("evidence_chain_verification is unsupported")
        if self.certificate_signature is not None and not isinstance(
            self.certificate_signature, CertificateSignature
        ):
            raise ExperimentValidationError("certificate_signature is invalid")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ExperimentRecord":
        _exact_fields(payload, EXPERIMENT_FIELDS, "experiment")
        signature_payload = payload["certificate_signature"]
        if signature_payload is not None and not isinstance(signature_payload, Mapping):
            raise ExperimentValidationError("certificate_signature is invalid")
        values = dict(payload)
        values["certificate_signature"] = (
            CertificateSignature.from_dict(signature_payload)
            if signature_payload is not None
            else None
        )
        return cls(**values)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ExperimentComparison:
    schema: str
    result_source: str
    real_campaign_result: bool
    description: str
    baseline: ExperimentRecord
    event_horizon: ExperimentRecord

    def __post_init__(self) -> None:
        if self.schema != "event-horizon.experiment-comparison.v1":
            raise ExperimentValidationError("comparison schema is unsupported")
        if self.result_source != "scripted-synthetic" or self.real_campaign_result is not False:
            raise ExperimentValidationError("comparison must remain labeled as scripted synthetic data")
        if not isinstance(self.description, str) or not self.description:
            raise ExperimentValidationError("comparison description is invalid")
        if self.baseline.mode != "baseline" or self.event_horizon.mode != "event-horizon":
            raise ExperimentValidationError("comparison modes are invalid")
        paired = (
            "range_image_digest",
            "attacker_configuration_digest",
            "policy_digest",
            "executor_measurement",
            "seed",
        )
        if any(getattr(self.baseline, name) != getattr(self.event_horizon, name) for name in paired):
            raise ExperimentValidationError("comparison inputs are not paired")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ExperimentComparison":
        _exact_fields(
            payload,
            {"schema", "result_source", "real_campaign_result", "description", "baseline", "event_horizon"},
            "comparison",
        )
        if not isinstance(payload["baseline"], Mapping) or not isinstance(payload["event_horizon"], Mapping):
            raise ExperimentValidationError("comparison records are invalid")
        return cls(
            schema=payload["schema"],
            result_source=payload["result_source"],
            real_campaign_result=payload["real_campaign_result"],
            description=payload["description"],
            baseline=ExperimentRecord.from_dict(payload["baseline"]),
            event_horizon=ExperimentRecord.from_dict(payload["event_horizon"]),
        )

    @classmethod
    def from_json(cls, data: str | bytes) -> "ExperimentComparison":
        payload = strict_json_loads(data)
        if not isinstance(payload, Mapping):
            raise ExperimentValidationError("comparison must be a JSON object")
        return cls.from_dict(payload)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_scripted_reference_comparison() -> ExperimentComparison:
    common: dict[str, Any] = {
        "schema": "event-horizon.experiment.v1",
        "result_source": "scripted-synthetic",
        "range_image_digest": digest("synthetic-range-image-v1"),
        "attacker_configuration_digest": digest("scripted-adversary-v1"),
        "policy_digest": digest("static-policy-v1"),
        "executor_measurement": digest("synthetic-executor-v1"),
        "seed": 4,
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-01-01T00:00:05Z",
        "credentials_discovered": 1,
        "capability_replay_attempts": 1,
        "cross_executor_attempts": 1,
        "evidence_tampering_attempts": 1,
        "persistence_after_teardown": None,
        "evidence_chain_verification": "not-measured",
        "certificate_signature": None,
    }
    baseline = ExperimentRecord.from_dict(
        {
            **common,
            "experiment_id": "scripted-baseline-reference",
            "mode": "baseline",
            "attestation_digest": None,
            "maximum_privilege_stage": "synthetic-lateral-access",
            "credentials_successfully_exercised": 1,
            "lateral_targets_reached": 1,
            "unauthorized_egress_bytes": 128,
        }
    )
    contained = ExperimentRecord.from_dict(
        {
            **common,
            "experiment_id": "scripted-event-horizon-reference",
            "mode": "event-horizon",
            "attestation_digest": digest("simulator-attestation-v1"),
            "maximum_privilege_stage": "synthetic-discovery",
            "credentials_successfully_exercised": 0,
            "lateral_targets_reached": 0,
            "unauthorized_egress_bytes": 0,
        }
    )
    return ExperimentComparison(
        schema="event-horizon.experiment-comparison.v1",
        result_source="scripted-synthetic",
        real_campaign_result=False,
        description=(
            "Deterministic harmless runner output; not a Nemesis result, real target result, "
            "or frontier-model containment result."
        ),
        baseline=baseline,
        event_horizon=contained,
    )
