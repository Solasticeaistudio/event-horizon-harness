from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes, digest
from .models import ActionRequest, CapabilityClaims, IssuedCapability


class CapabilityError(PermissionError):
    pass


class CapabilityBroker:
    """Prototype external capability signer and one-use verifier.

    The private key belongs outside the hostile execution environment. The
    executor needs only the Ed25519 public key. This single-process prototype
    keeps issuance and consumption state together until the process split.
    """

    def __init__(
        self,
        signing_key: bytes | Ed25519PrivateKey | None = None,
        key_id: str | None = None,
        ttl_seconds: float = 10.0,
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
        raw_public = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = key_id or f"ed25519:{hashlib.sha256(raw_public).hexdigest()[:32]}"
        self.ttl_seconds = ttl_seconds
        self._consumed: set[str] = set()
        self._lock = threading.RLock()

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
        executor_measurement: str,
        attestation_digest: str,
        policy_digest: str,
        max_output_bytes: int,
        now: float | None = None,
    ) -> IssuedCapability:
        now = time.time() if now is None else now
        claims = CapabilityClaims(
            capability_id=f"cap_{secrets.token_hex(12)}",
            issued_at=now,
            expires_at=now + self.ttl_seconds,
            session_id=request.session_id,
            agent_id=request.agent_id,
            executor_id=request.executor_id,
            executor_measurement=executor_measurement,
            attestation_digest=attestation_digest,
            operation=request.operation,
            resource_id=request.resource_id,
            arguments_digest=digest(dict(request.arguments)),
            request_digest=request.request_digest,
            max_output_bytes=max_output_bytes,
            invocation_limit=1,
            policy_digest=policy_digest,
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
        now: float | None = None,
    ) -> CapabilityClaims:
        now = time.time() if now is None else now
        claims = capability.claims
        if capability.key_id != self.key_id:
            raise CapabilityError("unknown capability signing key")
        try:
            padding = "=" * (-len(capability.signature) % 4)
            signature = base64.urlsafe_b64decode(capability.signature + padding)
            self._public_key.verify(signature, canonical_bytes(claims.to_dict()))
        except (InvalidSignature, ValueError) as exc:
            raise CapabilityError("invalid capability signature") from exc
        if now > claims.expires_at:
            raise CapabilityError("capability expired")
        if claims.invocation_limit != 1:
            raise CapabilityError("unsupported invocation limit")
        bindings = {
            "session_id": (claims.session_id, request.session_id),
            "agent_id": (claims.agent_id, request.agent_id),
            "executor_id": (claims.executor_id, request.executor_id),
            "executor_measurement": (claims.executor_measurement, executor_measurement),
            "operation": (claims.operation, request.operation),
            "resource_id": (claims.resource_id, request.resource_id),
            "arguments_digest": (claims.arguments_digest, digest(dict(request.arguments))),
            "request_digest": (claims.request_digest, request.request_digest),
        }
        mismatches = [name for name, (expected_value, actual_value) in bindings.items() if expected_value != actual_value]
        if mismatches:
            raise CapabilityError(f"capability binding mismatch: {sorted(mismatches)}")
        with self._lock:
            if claims.capability_id in self._consumed:
                raise CapabilityError("capability replay detected")
            self._consumed.add(claims.capability_id)
        return claims
