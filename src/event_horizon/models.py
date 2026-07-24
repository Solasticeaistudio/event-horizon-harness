from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Mapping

from .canonical import digest


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ActionRequest:
    request_id: str
    session_id: str
    agent_id: str
    operation: str
    resource_id: str
    executor_id: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    purpose: str = ""

    ALLOWED_FIELDS = frozenset({
        "request_id", "session_id", "agent_id", "operation", "resource_id",
        "executor_id", "arguments", "purpose"
    })

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ActionRequest":
        if not isinstance(payload, Mapping):
            raise ValidationError("request must be an object")
        unknown = set(payload) - cls.ALLOWED_FIELDS
        if unknown:
            raise ValidationError(f"unknown fields: {sorted(unknown)}")
        required = cls.ALLOWED_FIELDS - {"arguments", "purpose"}
        missing = [key for key in required if not payload.get(key)]
        if missing:
            raise ValidationError(f"missing required fields: {sorted(missing)}")
        arguments = payload.get("arguments", {})
        if not isinstance(arguments, Mapping):
            raise ValidationError("arguments must be an object")
        for key in ("request_id", "session_id", "agent_id", "operation", "resource_id", "executor_id"):
            value = payload[key]
            if not isinstance(value, str) or len(value) > 256:
                raise ValidationError(f"{key} must be a non-empty string <= 256 characters")
        purpose = payload.get("purpose", "")
        if not isinstance(purpose, str) or len(purpose) > 1024:
            raise ValidationError("purpose must be a string <= 1024 characters")
        return cls(
            request_id=payload["request_id"],
            session_id=payload["session_id"],
            agent_id=payload["agent_id"],
            operation=payload["operation"],
            resource_id=payload["resource_id"],
            executor_id=payload["executor_id"],
            arguments=dict(arguments),
            purpose=purpose,
        )

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "operation": self.operation,
            "resource_id": self.resource_id,
            "executor_id": self.executor_id,
            "arguments": dict(self.arguments),
            "purpose": self.purpose,
        }

    @property
    def request_digest(self) -> str:
        return digest(self.canonical_payload())


@dataclass(frozen=True)
class GuardianDecision:
    guardian: str
    allowed: bool
    reason: str
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CapabilityClaims:
    capability_id: str
    issued_at: float
    expires_at: float
    session_id: str
    agent_id: str
    executor_id: str
    executor_measurement: str
    attestation_digest: str
    operation: str
    resource_id: str
    arguments_digest: str
    request_digest: str
    max_output_bytes: int
    invocation_limit: int = 1
    policy_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IssuedCapability:
    claims: CapabilityClaims
    signature: str
    key_id: str

    def to_dict(self) -> dict[str, Any]:
        return {"claims": self.claims.to_dict(), "signature": self.signature, "key_id": self.key_id}


@dataclass(frozen=True)
class ExecutionResult:
    success: bool
    operation: str
    resource_id: str
    output: Any = None
    output_bytes: int = 0
    error: str | None = None
