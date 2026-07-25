from __future__ import annotations

import base64
import hashlib
import math
import re
import secrets
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes, digest
from .models import ActionRequest, CapabilityClaims, IssuedCapability
from .replay_state import CapabilityConsumptionStore, InMemoryCapabilityConsumptionStore


class CapabilityError(PermissionError):
    pass


def capability_key_id(public_key: Ed25519PublicKey) -> str:
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(raw_public).hexdigest()[:32]}"


def _strict_signature(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}", value):
        raise CapabilityError("malformed capability signature")
    try:
        signature = base64.urlsafe_b64decode(value + "==")
    except (ValueError, TypeError) as exc:
        raise CapabilityError("malformed capability signature") from exc
    if len(signature) != 64 or base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") != value:
        raise CapabilityError("malformed capability signature")
    return signature


def _now_ms(now: float | None) -> int:
    seconds = time.time() if now is None else now
    if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or not math.isfinite(seconds):
        raise CapabilityError("verification clock is invalid")
    return int(seconds * 1000)


def _verified_claims(
    public_key: Ed25519PublicKey,
    expected_key_id: str,
    capability: IssuedCapability,
    request: ActionRequest,
    *,
    executor_measurement: str,
    device_id: str | None,
    attestation_digest: str | None,
    attestation_bundle_digest: str | None,
    verifier_policy_digest: str | None,
    policy_digest: str | None,
    now: float | None,
) -> CapabilityClaims:
    try:
        parsed = IssuedCapability.from_dict(capability.to_dict())
    except (TypeError, ValueError) as exc:
        raise CapabilityError(f"malformed capability: {exc}") from exc
    claims = parsed.claims
    if parsed.algorithm != "Ed25519":
        raise CapabilityError("unsupported capability algorithm")
    if parsed.key_id != expected_key_id or claims.signer_key_id != expected_key_id:
        raise CapabilityError("unknown capability signing key")
    try:
        public_key.verify(_strict_signature(parsed.signature), canonical_bytes(claims.to_dict()))
    except InvalidSignature as exc:
        raise CapabilityError("invalid capability signature") from exc

    current_ms = _now_ms(now)
    if current_ms < claims.issued_at - 5_000:
        raise CapabilityError("capability issued beyond allowed clock skew")
    if current_ms >= claims.expires_at:
        raise CapabilityError("capability expired")

    def expected(value: str | None, fallback: str) -> str:
        return fallback if value is None else value

    request_payload = request.canonical_payload()
    reconstructed_request_digest = digest(request_payload)
    reconstructed_arguments_digest = digest(request_payload["arguments"])
    bindings = {
        "session_id": (claims.session_id, request.session_id),
        "agent_id": (claims.agent_id, request.agent_id),
        "executor_id": (claims.executor_id, request.executor_id),
        "device_id": (claims.device_id, expected(device_id, claims.device_id)),
        "executor_measurement": (claims.executor_measurement, executor_measurement),
        "attestation_digest": (claims.attestation_digest, expected(attestation_digest, claims.attestation_digest)),
        "attestation_bundle_digest": (
            claims.attestation_bundle_digest,
            expected(attestation_bundle_digest, claims.attestation_bundle_digest),
        ),
        "verifier_policy_digest": (
            claims.verifier_policy_digest,
            expected(verifier_policy_digest, claims.verifier_policy_digest),
        ),
        "policy_digest": (claims.policy_digest, expected(policy_digest, claims.policy_digest)),
        "signer_key_id": (claims.signer_key_id, parsed.key_id),
        "operation": (claims.operation, request.operation),
        "resource_id": (claims.resource_id, request.resource_id),
        "arguments_digest": (claims.arguments_digest, reconstructed_arguments_digest),
        "request_digest": (claims.request_digest, reconstructed_request_digest),
    }
    mismatches = [name for name, pair in bindings.items() if pair[0] != pair[1]]
    if mismatches:
        raise CapabilityError(f"capability binding mismatch: {sorted(mismatches)}")
    return claims


def _consume_once(
    store: CapabilityConsumptionStore,
    claims: CapabilityClaims,
    now: float | None,
) -> None:
    try:
        accepted = store.consume(
            claims.capability_id,
            digest(claims.to_dict()),
            claims.expires_at,
            _now_ms(now),
        )
    except Exception as exc:
        raise CapabilityError("capability replay state unavailable") from exc
    if not accepted:
        raise CapabilityError("capability replay detected")


class CapabilityVerifier:
    """Public-key-only verifier with injected one-use consumption state."""

    def __init__(
        self,
        public_key: str | bytes | Ed25519PublicKey,
        key_id: str,
        consumption_store: CapabilityConsumptionStore | None = None,
    ):
        if isinstance(public_key, Ed25519PublicKey):
            loaded = public_key
        else:
            encoded = public_key.encode("ascii") if isinstance(public_key, str) else public_key
            loaded = serialization.load_pem_public_key(encoded)
        if not isinstance(loaded, Ed25519PublicKey):
            raise TypeError("capability verification key must be Ed25519")
        actual_key_id = capability_key_id(loaded)
        if key_id != actual_key_id:
            raise ValueError("capability key_id does not match the supplied public key")
        self._public_key = loaded
        self.key_id = actual_key_id
        self.consumption_store = consumption_store or InMemoryCapabilityConsumptionStore()

    def verify_and_consume(
        self,
        capability: IssuedCapability,
        request: ActionRequest,
        *,
        executor_measurement: str,
        device_id: str | None = None,
        attestation_digest: str | None = None,
        attestation_bundle_digest: str | None = None,
        verifier_policy_digest: str | None = None,
        policy_digest: str | None = None,
        now: float | None = None,
    ) -> CapabilityClaims:
        claims = _verified_claims(
            self._public_key, self.key_id, capability, request,
            executor_measurement=executor_measurement,
            device_id=device_id,
            attestation_digest=attestation_digest,
            attestation_bundle_digest=attestation_bundle_digest,
            verifier_policy_digest=verifier_policy_digest,
            policy_digest=policy_digest,
            now=now,
        )
        _consume_once(self.consumption_store, claims, now)
        return claims


class CapabilityBroker:
    """External capability signer and one-use verifier.

    The private key belongs outside the hostile execution environment. The
    executor needs only the Ed25519 public key. Production call sites must
    inject replay state shared by every replica in the same consumption domain.
    """

    def __init__(
        self,
        signing_key: bytes | Ed25519PrivateKey | None = None,
        key_id: str | None = None,
        ttl_seconds: float = 10.0,
        consumption_store: CapabilityConsumptionStore | None = None,
    ):
        if isinstance(signing_key, Ed25519PrivateKey):
            self._private_key = signing_key
        elif isinstance(signing_key, bytes):
            if len(signing_key) < 32:
                raise ValueError("signing key seed must be at least 32 bytes")
            self._private_key = Ed25519PrivateKey.from_private_bytes(signing_key[:32])
        elif signing_key is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            raise TypeError("unsupported signing key")
        self._public_key = self._private_key.public_key()
        actual_key_id = capability_key_id(self._public_key)
        if key_id is not None and key_id != actual_key_id:
            raise ValueError("explicit capability key_id does not match the signing key")
        self.key_id = actual_key_id
        if not isinstance(ttl_seconds, (int, float)) or isinstance(ttl_seconds, bool) or not math.isfinite(ttl_seconds):
            raise ValueError("capability TTL must be finite")
        if not 0 < ttl_seconds <= 300:
            raise ValueError("capability TTL must be greater than zero and at most 300 seconds")
        self.ttl_seconds = ttl_seconds
        self.consumption_store = consumption_store or InMemoryCapabilityConsumptionStore()

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def issue(
        self,
        request: ActionRequest,
        *,
        device_id: str,
        executor_measurement: str,
        attestation_digest: str,
        attestation_bundle_digest: str,
        verifier_policy_digest: str,
        policy_digest: str,
        max_output_bytes: int,
        now: float | None = None,
    ) -> IssuedCapability:
        issued_at = _now_ms(now)
        ttl_ms = max(1, math.ceil(self.ttl_seconds * 1000))
        request_payload = request.canonical_payload()
        request_digest = digest(request_payload)
        arguments_digest = digest(request_payload["arguments"])
        claims = CapabilityClaims(
            capability_id=f"cap_{secrets.token_hex(12)}",
            issued_at=issued_at,
            expires_at=issued_at + ttl_ms,
            session_id=request.session_id,
            agent_id=request.agent_id,
            executor_id=request.executor_id,
            device_id=device_id,
            executor_measurement=executor_measurement,
            attestation_digest=attestation_digest,
            attestation_bundle_digest=attestation_bundle_digest,
            verifier_policy_digest=verifier_policy_digest,
            operation=request.operation,
            resource_id=request.resource_id,
            arguments_digest=arguments_digest,
            request_digest=request_digest,
            max_output_bytes=max_output_bytes,
            invocation_limit=1,
            policy_digest=policy_digest,
            signer_key_id=self.key_id,
        )
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(claims.to_dict()))
        ).rstrip(b"=").decode("ascii")
        return IssuedCapability(claims=claims, signature=signature, key_id=self.key_id)

    def verify_and_consume(
        self,
        capability: IssuedCapability,
        request: ActionRequest,
        *,
        executor_measurement: str,
        device_id: str | None = None,
        attestation_digest: str | None = None,
        attestation_bundle_digest: str | None = None,
        verifier_policy_digest: str | None = None,
        policy_digest: str | None = None,
        now: float | None = None,
    ) -> CapabilityClaims:
        claims = _verified_claims(
            self._public_key, self.key_id, capability, request,
            executor_measurement=executor_measurement,
            device_id=device_id,
            attestation_digest=attestation_digest,
            attestation_bundle_digest=attestation_bundle_digest,
            verifier_policy_digest=verifier_policy_digest,
            policy_digest=policy_digest,
            now=now,
        )
        _consume_once(self.consumption_store, claims, now)
        return claims
