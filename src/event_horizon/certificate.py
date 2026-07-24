from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes
from .recorder import ExternalRecorder


class ContainmentCertificateBuilder:
    def __init__(
        self,
        recorder: ExternalRecorder,
        signing_key: bytes | Ed25519PrivateKey | None = None,
        key_id: str | None = None,
    ):
        self.recorder = recorder
        if isinstance(signing_key, Ed25519PrivateKey):
            self._private_key = signing_key
        elif isinstance(signing_key, bytes):
            if len(signing_key) < 32:
                raise ValueError("certificate signing seed must be at least 32 bytes")
            self._private_key = Ed25519PrivateKey.from_private_bytes(signing_key[:32])
        elif signing_key is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            raise TypeError("unsupported certificate signing key")
        self._public_key = self._private_key.public_key()
        raw_public = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = key_id or f"ed25519:{hashlib.sha256(raw_public).hexdigest()[:32]}"

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def build(self, *, run_id: str, session_id: str, assertions: dict[str, bool]) -> dict[str, Any]:
        valid, tip = self.recorder.verify()
        events = self.recorder.events()
        denied = sum(1 for event in events if event["event_type"] in {"request.denied", "execution.denied", "request.rejected"})
        completed = sum(1 for event in events if event["event_type"] == "execution.completed")
        hardproof_decisions = [
            event for event in events
            if event["event_type"] == "guardian.decision" and event["payload"].get("guardian") == "hardproof"
        ]
        attestation_digests = sorted({
            event["payload"].get("evidence", {}).get("bundle_digest")
            for event in hardproof_decisions
            if event["payload"].get("evidence", {}).get("bundle_digest")
        })
        payload = {
            "schema": "event-horizon.containment-certificate.v0.3",
            "run_id": run_id,
            "session_id": session_id,
            "created_at": time.time(),
            "event_count": len(events),
            "event_chain_valid": valid,
            "event_chain_tip": tip,
            "completed_actions": completed,
            "denied_transitions": denied,
            "hardproof_attestation_digests": attestation_digests,
            "assertions": dict(sorted(assertions.items())),
        }
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(payload))
        ).rstrip(b"=").decode("ascii")
        return {
            "certificate": payload,
            "signature": signature,
            "algorithm": "Ed25519",
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
        }

    @staticmethod
    def verify(certificate: dict[str, Any]) -> bool:
        try:
            payload = certificate["certificate"]
            public_key = serialization.load_pem_public_key(certificate["public_key_pem"].encode("ascii"))
            if not isinstance(public_key, Ed25519PublicKey):
                return False
            padding = "=" * (-len(certificate["signature"]) % 4)
            signature = base64.urlsafe_b64decode(certificate["signature"] + padding)
            public_key.verify(signature, canonical_bytes(payload))
            return True
        except (KeyError, ValueError, InvalidSignature):
            return False

    def write(self, path: str | Path, **kwargs: Any) -> dict[str, Any]:
        result = self.build(**kwargs)
        Path(path).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        return result
