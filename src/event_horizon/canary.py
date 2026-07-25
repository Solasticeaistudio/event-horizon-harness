from __future__ import annotations

import base64
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .broker import capability_key_id
from .canonical import canonical_bytes, digest
from .models import ActionRequest, ValidationError
from .recorder import ExternalRecorder


CANARY_SCHEMA = "event-horizon.canary-capability.v1"
CANARY_EVENT_TYPES = frozenset({"discovery", "inspection", "mutation", "transfer", "redemption"})
SUBTRACTIVE_RESPONSES = frozenset({
    "deny", "reduce-budget", "remove-tools", "revoke-capabilities", "require-reattestation",
    "quarantine", "terminate", "human-review", "hardware-safe-state",
})
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CANARY_ID = re.compile(r"^canary_[0-9a-f]{24}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")


class CanaryError(PermissionError):
    pass


def _text(value: Any, name: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ValidationError(f"{name} must be a non-empty bounded string")
    canonical_bytes(value)
    return value


@dataclass(frozen=True)
class CanaryClaims:
    schema: str
    canary_id: str
    campaign_id: str
    session_id: str
    workload_id: str
    tenant: str
    environment: str
    seed_location: str
    version: str
    policy_version: str
    issued_at_ms: int
    expires_at_ms: int
    representation_digest: str
    canary_status: str = "non-effect-tripwire"

    FIELDS = frozenset({
        "schema", "canary_id", "campaign_id", "session_id", "workload_id", "tenant",
        "environment", "seed_location", "version", "policy_version", "issued_at_ms",
        "expires_at_ms", "representation_digest", "canary_status",
    })

    def __post_init__(self) -> None:
        if self.schema != CANARY_SCHEMA or self.canary_status != "non-effect-tripwire":
            raise ValidationError("canary schema or status is invalid")
        if not _CANARY_ID.fullmatch(self.canary_id):
            raise ValidationError("canary ID is malformed")
        for name in (
            "campaign_id", "session_id", "workload_id", "tenant", "environment",
            "seed_location", "version", "policy_version",
        ):
            _text(getattr(self, name), name)
        if type(self.issued_at_ms) is not int or type(self.expires_at_ms) is not int:
            raise ValidationError("canary timestamps must be integers")
        if not 0 < self.expires_at_ms - self.issued_at_ms <= 300_000:
            raise ValidationError("canary lifetime is invalid")
        if not _DIGEST.fullmatch(self.representation_digest):
            raise ValidationError("canary representation digest is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CanaryClaims":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ValidationError("canary claim fields are invalid")
        return cls(**dict(value))


@dataclass(frozen=True)
class CanaryCapability:
    claims: CanaryClaims
    signature: str
    key_id: str
    algorithm: str = "Ed25519"

    def __post_init__(self) -> None:
        if self.algorithm != "Ed25519" or not _SIGNATURE.fullmatch(self.signature):
            raise ValidationError("canary signature envelope is invalid")
        _text(self.key_id, "canary key ID", 64)

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "canary_claims": self.claims.to_dict(),
            "signature": self.signature,
            "key_id": self.key_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CanaryCapability":
        if not isinstance(value, Mapping) or set(value) != {
            "algorithm", "canary_claims", "signature", "key_id"
        }:
            raise ValidationError("canary envelope fields are invalid")
        return cls(
            CanaryClaims.from_dict(value["canary_claims"]),
            value["signature"],
            value["key_id"],
            value["algorithm"],
        )


@dataclass(frozen=True)
class CanaryResponsePolicy:
    actions: tuple[str, ...] = ("deny", "revoke-capabilities", "quarantine")

    def __post_init__(self) -> None:
        if not self.actions or len(set(self.actions)) != len(self.actions):
            raise ValueError("canary response actions must be unique and non-empty")
        if set(self.actions) - SUBTRACTIVE_RESPONSES:
            raise ValueError("canary response may contain only subtractive actions")


class CanaryAuthority:
    """Trusted issuer for non-effect tripwires; never exposed to the hostile cell."""

    def __init__(self, signing_key: bytes | Ed25519PrivateKey | None = None):
        if isinstance(signing_key, Ed25519PrivateKey):
            self._private_key = signing_key
        elif isinstance(signing_key, bytes) and len(signing_key) >= 32:
            self._private_key = Ed25519PrivateKey.from_private_bytes(signing_key[:32])
        elif signing_key is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            raise ValueError("canary signing key must contain at least 32 bytes")
        self._public_key = self._private_key.public_key()
        self.key_id = capability_key_id(self._public_key)

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def issue(
        self,
        *,
        campaign_id: str,
        session_id: str,
        workload_id: str,
        tenant: str,
        environment: str,
        seed_location: str,
        policy_version: str,
        representation: Mapping[str, Any],
        now_ms: int | None = None,
        ttl_ms: int = 60_000,
        enabled: bool = False,
        production: bool = False,
    ) -> CanaryCapability:
        if not enabled:
            raise CanaryError("canary seeding is disabled")
        if production:
            raise CanaryError("test canaries cannot be seeded in production configuration")
        issued_at = int(time.time() * 1000) if now_ms is None else now_ms
        claims = CanaryClaims(
            schema=CANARY_SCHEMA,
            canary_id=f"canary_{secrets.token_hex(12)}",
            campaign_id=campaign_id,
            session_id=session_id,
            workload_id=workload_id,
            tenant=tenant,
            environment=environment,
            seed_location=seed_location,
            version="v1",
            policy_version=policy_version,
            issued_at_ms=issued_at,
            expires_at_ms=issued_at + ttl_ms,
            representation_digest=digest(representation),
        )
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(claims.to_dict()))
        ).rstrip(b"=").decode("ascii")
        return CanaryCapability(claims, signature, self.key_id)


class CanaryVerifier:
    """Public-key-only tripwire verifier. Every redemption is a denial."""

    def __init__(
        self,
        public_key: str | bytes | Ed25519PublicKey,
        key_id: str,
        recorder: ExternalRecorder,
        *,
        tenant: str,
        environment: str,
        response_policy: CanaryResponsePolicy = CanaryResponsePolicy(),
        clock_ms: Callable[[], int] | None = None,
    ):
        if isinstance(public_key, Ed25519PublicKey):
            loaded = public_key
        else:
            encoded = public_key.encode("ascii") if isinstance(public_key, str) else public_key
            loaded = serialization.load_pem_public_key(encoded)
        if not isinstance(loaded, Ed25519PublicKey) or capability_key_id(loaded) != key_id:
            raise ValueError("canary public key identity mismatch")
        self._public_key = loaded
        self.key_id = key_id
        self.recorder = recorder
        self.tenant = _text(tenant, "canary verifier tenant")
        self.environment = _text(environment, "canary verifier environment")
        self.response_policy = response_policy
        self._clock_ms = clock_ms or (lambda: int(time.time() * 1000))

    def _verified(self, capability: CanaryCapability, now_ms: int) -> CanaryClaims:
        parsed = CanaryCapability.from_dict(capability.to_dict())
        if parsed.key_id != self.key_id:
            raise CanaryError("unknown canary signing key")
        try:
            raw = base64.urlsafe_b64decode(parsed.signature + "==")
            self._public_key.verify(raw, canonical_bytes(parsed.claims.to_dict()))
        except (InvalidSignature, ValueError) as exc:
            raise CanaryError("invalid canary signature") from exc
        claims = parsed.claims
        if now_ms < claims.issued_at_ms - 5_000 or now_ms >= claims.expires_at_ms:
            raise CanaryError("canary is not currently valid")
        if claims.tenant != self.tenant or claims.environment != self.environment:
            raise CanaryError("canary tenant or environment mismatch")
        return claims

    def record_interaction(
        self,
        event_type: str,
        capability: CanaryCapability,
        *,
        request: ActionRequest | None = None,
        representation: Mapping[str, Any] | None = None,
        mutation_diff: Mapping[str, Any] | None = None,
        now_ms: int | None = None,
    ) -> dict[str, Any]:
        if event_type not in CANARY_EVENT_TYPES:
            raise CanaryError("unsupported canary event type")
        current = self._clock_ms() if now_ms is None else now_ms
        claims = self._verified(capability, current)
        if request is not None and (
            request.session_id != claims.session_id
            or request.executor_id != claims.workload_id
        ):
            event_type = "transfer"
        if representation is not None and digest(representation) != claims.representation_digest:
            event_type = "mutation"
        payload = {
            "canary_id": claims.canary_id,
            "session_id": claims.session_id,
            "workload_id": claims.workload_id,
            "tenant": claims.tenant,
            "environment": claims.environment,
            "seed_location": claims.seed_location,
            "attempted_action": request.operation if request else "inspect",
            "attempted_resource": request.resource_id if request else claims.seed_location,
            "mutation_diff": dict(mutation_diff or {}),
            "timestamp_ms": current,
            "policy_version": claims.policy_version,
            "trust_state": "not-authority",
            "campaign_id": claims.campaign_id,
            "responses": list(self.response_policy.actions),
        }
        payload["evidence_hash"] = digest(payload)
        self.recorder.append(f"canary.{event_type}", payload)
        return payload

    def redeem(
        self,
        capability: CanaryCapability,
        request: ActionRequest,
        *,
        representation: Mapping[str, Any] | None = None,
        now_ms: int | None = None,
    ) -> None:
        self.record_interaction(
            "redemption",
            capability,
            request=request,
            representation=representation,
            now_ms=now_ms,
        )
        raise CanaryError("canary capabilities are non-effect tripwires and cannot be redeemed")


def is_canary_capability(value: object) -> bool:
    return isinstance(value, CanaryCapability)


def canary_ids_do_not_overlap(capability_ids: Sequence[str], canary_ids: Sequence[str]) -> bool:
    return not set(capability_ids) & set(canary_ids) and all(
        item.startswith("cap_") for item in capability_ids
    ) and all(item.startswith("canary_") for item in canary_ids)
