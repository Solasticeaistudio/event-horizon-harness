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
    device_id: str
    executor_measurement: str
    attestation_digest: str
    attestation_bundle_digest: str
    verifier_policy_digest: str
    operation: str
    resource_id: str
    arguments_digest: str
    request_digest: str
    max_output_bytes: int
    invocation_limit: int = 1
    signer_key_id: str = ""
    policy_digest: str = ""

    ALLOWED_FIELDS = frozenset({
        'capability_id', 'issued_at', 'expires_at', 'session_id', 'agent_id',
        'executor_id', 'device_id', 'executor_measurement', 'attestation_digest',
        'attestation_bundle_digest', 'verifier_policy_digest', 'operation',
        'resource_id', 'arguments_digest', 'request_digest', 'max_output_bytes',
        'invocation_limit', 'policy_digest', 'signer_key_id',
    })

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> 'CapabilityClaims':
        if not isinstance(payload, Mapping):
            raise ValidationError('capability claims must be an object')
        unknown = set(payload) - cls.ALLOWED_FIELDS
        missing = cls.ALLOWED_FIELDS - set(payload)
        if unknown or missing:
            raise ValidationError(
                f'invalid capability claim fields; unknown={sorted(unknown)}, missing={sorted(missing)}'
            )
        string_fields = cls.ALLOWED_FIELDS - {
            'issued_at', 'expires_at', 'max_output_bytes', 'invocation_limit'
        }
        if any(not isinstance(payload[name], str) or not payload[name] for name in string_fields):
            raise ValidationError('capability string claims must be non-empty strings')
        if not isinstance(payload['issued_at'], (int, float)) or not isinstance(payload['expires_at'], (int, float)):
            raise ValidationError('capability timestamps must be numbers')
        output_limit = payload['max_output_bytes']
        if not isinstance(output_limit, int) or not 0 < output_limit <= 1_048_576:
            raise ValidationError('invalid capability output limit')
        if payload['invocation_limit'] != 1:
            raise ValidationError('only one-use capabilities are supported')
        return cls(**dict(payload))


@dataclass(frozen=True)
class IssuedCapability:
    claims: CapabilityClaims
    signature: str
    key_id: str

    def to_dict(self) -> dict[str, Any]:
        return {"claims": self.claims.to_dict(), "signature": self.signature, "key_id": self.key_id}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> 'IssuedCapability':
        if not isinstance(payload, Mapping) or set(payload) != {'claims', 'signature', 'key_id'}:
            raise ValidationError('capability envelope fields are invalid')
        signature = payload['signature']
        key_id = payload['key_id']
        if not isinstance(signature, str) or not signature or not isinstance(key_id, str) or not key_id:
            raise ValidationError('capability signature and key_id are required')
        return cls(CapabilityClaims.from_dict(payload['claims']), signature, key_id)


@dataclass(frozen=True)
class ExecutionResult:
    success: bool
    operation: str
    resource_id: str
    output: Any = None
    output_bytes: int = 0
    error: str | None = None
