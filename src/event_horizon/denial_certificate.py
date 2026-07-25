from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Mapping, MutableSet

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes
from .models import ValidationError
from .recorder import ExternalRecorder


DENIAL_SCHEMA = "event-horizon.denial-certificate.v1"
EFFECT_STATES = frozenset({
    "denied-before-effect", "denied-after-validation", "indeterminate-crash",
    "effect-committed-response-lost", "reconciliation-required",
})
KNOWN_NO_EFFECT_STATES = frozenset({"denied-before-effect", "denied-after-validation"})
AMBIGUOUS_EFFECT_STATES = frozenset({"indeterminate-crash", "reconciliation-required"})
ARCHIVAL_STATES = frozenset({"active", "archived", "revoked"})
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^ed25519:[0-9a-f]{32}$")
_CERTIFICATE_ID = re.compile(r"^deny_[0-9a-f]{24}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_PRIVATE_KEYS = frozenset({
    "password", "secret", "token", "credential", "api_key", "authorization",
    "private_key", "prompt", "natural_language_task",
})


class DenialCertificateError(RuntimeError):
    pass


def _text(value: Any, name: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ValidationError(f"{name} must be a non-empty bounded string")
    canonical_bytes(value)
    return value


def _sha(value: Any, name: str) -> str:
    text = _text(value, name, 64)
    if not _DIGEST.fullmatch(text):
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
    return text


def _privacy_safe(value: Any, path: str = "authority") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in _PRIVATE_KEYS:
                raise ValidationError(f"{path} contains a prohibited private field")
            _privacy_safe(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for item in value:
            _privacy_safe(item, path)
    elif isinstance(value, str) and len(value.encode("utf-8")) > 512:
        raise ValidationError(f"{path} contains an oversized string")
    canonical_bytes(value)


def _key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"


@dataclass(frozen=True)
class DenialVerificationResult:
    valid: bool
    reason: str
    certificate_id: str | None = None
    effect_state: str | None = None


class DenialCertificateBuilder:
    """Signs a receipt for one evaluated denial or ambiguous effect outcome."""

    def __init__(
        self,
        recorder: ExternalRecorder,
        signing_key: bytes | Ed25519PrivateKey | None = None,
    ):
        self.recorder = recorder
        if isinstance(signing_key, Ed25519PrivateKey):
            self._private_key = signing_key
        elif isinstance(signing_key, bytes) and len(signing_key) >= 32:
            self._private_key = Ed25519PrivateKey.from_private_bytes(signing_key[:32])
        elif signing_key is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            raise ValueError("denial certificate signing key must contain at least 32 bytes")
        self._public_key = self._private_key.public_key()
        self.key_id = _key_id(self._public_key)

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def build(
        self,
        *,
        attempt_id: str,
        task_id: str,
        session_id: str,
        workload_identity_hash: str,
        technique_classification: str,
        request_digest: str,
        canonical_request_digest: str,
        requested_authority: Mapping[str, Any],
        effective_authority: Mapping[str, Any],
        denial_reason_code: str,
        effect_state: str,
        policy_version: str,
        policy_digest: str,
        policy_ceiling_digest: str,
        synthesizer_version: str,
        compiler_version: str,
        provider_attestation_digest: str,
        guardian_state_digest: str,
        decay_state_digest: str,
        code_commit: str,
        build_identifier: str,
        environment_identifier: str,
        campaign_id: str | None = None,
        denial_timestamp_ms: int | None = None,
        archival_status: str = "active",
    ) -> dict[str, Any]:
        for name, value in (
            ("attempt ID", attempt_id), ("task ID", task_id), ("session ID", session_id),
            ("technique classification", technique_classification),
            ("denial reason", denial_reason_code), ("policy version", policy_version),
            ("synthesizer version", synthesizer_version), ("compiler version", compiler_version),
            ("code commit", code_commit), ("build identifier", build_identifier),
            ("environment identifier", environment_identifier),
        ):
            _text(value, name)
        if campaign_id is not None:
            _text(campaign_id, "campaign ID")
        for name, value in (
            ("workload identity hash", workload_identity_hash),
            ("request digest", request_digest),
            ("canonical request digest", canonical_request_digest),
            ("policy digest", policy_digest),
            ("policy ceiling digest", policy_ceiling_digest),
            ("provider attestation digest", provider_attestation_digest),
            ("guardian state digest", guardian_state_digest),
            ("decay state digest", decay_state_digest),
        ):
            _sha(value, name)
        if effect_state not in EFFECT_STATES:
            raise ValidationError("denial effect state is invalid")
        if archival_status not in ARCHIVAL_STATES:
            raise ValidationError("denial archival status is invalid")
        _privacy_safe(requested_authority, "requested authority")
        _privacy_safe(effective_authority, "effective authority")
        timestamp = int(time.time() * 1000) if denial_timestamp_ms is None else denial_timestamp_ms
        if type(timestamp) is not int or timestamp < 0:
            raise ValidationError("denial timestamp must be a non-negative integer")
        no_effect: bool | None
        if effect_state in KNOWN_NO_EFFECT_STATES:
            no_effect = True
        elif effect_state == "effect-committed-response-lost":
            no_effect = False
        else:
            no_effect = None
        event_payload = {
            "attempt_id": attempt_id,
            "task_id": task_id,
            "session_id": session_id,
            "request_digest": request_digest,
            "denial_reason_code": denial_reason_code,
            "effect_state": effect_state,
            "no_authorized_effect_committed": no_effect,
            "policy_digest": policy_digest,
            "policy_ceiling_digest": policy_ceiling_digest,
            "provider_attestation_digest": provider_attestation_digest,
            "guardian_state_digest": guardian_state_digest,
            "decay_state_digest": decay_state_digest,
            "denial_timestamp_ms": timestamp,
        }
        event = self.recorder.append("denial.evaluated", event_payload)
        valid, root = self.recorder.verify()
        if not valid or root != event["event_hash"]:
            raise DenialCertificateError("denial evidence is not the verified chain tip")
        reference = {
            "sequence": event["sequence"],
            "event_hash": event["event_hash"],
            "event_type": event["event_type"],
        }
        payload = {
            "certificate_version": DENIAL_SCHEMA,
            "certificate_id": f"deny_{secrets.token_hex(12)}",
            "attempt_id": attempt_id,
            "campaign_id": campaign_id,
            "task_id": task_id,
            "session_id": session_id,
            "workload_identity_hash": workload_identity_hash,
            "technique_classification": technique_classification,
            "request_digest": request_digest,
            "canonical_request_digest": canonical_request_digest,
            "requested_authority": dict(requested_authority),
            "effective_authority": dict(effective_authority),
            "denial_reason_code": denial_reason_code,
            "effect_state": effect_state,
            "no_authorized_effect_committed": no_effect,
            "policy_version": policy_version,
            "policy_digest": policy_digest,
            "policy_ceiling_digest": policy_ceiling_digest,
            "synthesizer_version": synthesizer_version,
            "compiler_version": compiler_version,
            "provider_attestation_digest": provider_attestation_digest,
            "guardian_state_digest": guardian_state_digest,
            "decay_state_digest": decay_state_digest,
            "code_commit": code_commit,
            "build_identifier": build_identifier,
            "environment_identifier": environment_identifier,
            "evidence_chain_root": root,
            "relevant_evidence_references": [reference],
            "denial_timestamp_ms": timestamp,
            "signer_key_id": self.key_id,
            "signature_algorithm": "Ed25519",
            "archival_status": archival_status,
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
            "recorder_public_key_pem": self.recorder.public_key_pem,
            "recorder_receipt": event["receipt"],
        }


class DenialCertificateVerifier:
    ENVELOPE_FIELDS = frozenset({
        "certificate", "signature", "algorithm", "key_id", "public_key_pem",
        "recorder_public_key_pem", "recorder_receipt",
    })
    PAYLOAD_FIELDS = frozenset({
        "certificate_version", "certificate_id", "attempt_id", "campaign_id", "task_id",
        "session_id", "workload_identity_hash", "technique_classification", "request_digest",
        "canonical_request_digest", "requested_authority", "effective_authority",
        "denial_reason_code", "effect_state", "no_authorized_effect_committed",
        "policy_version", "policy_digest", "policy_ceiling_digest", "synthesizer_version",
        "compiler_version", "provider_attestation_digest", "guardian_state_digest",
        "decay_state_digest", "code_commit", "build_identifier", "environment_identifier",
        "evidence_chain_root", "relevant_evidence_references", "denial_timestamp_ms",
        "signer_key_id", "signature_algorithm", "archival_status",
    })

    def __init__(
        self,
        trusted_signer_public_key: str,
        *,
        trusted_recorder_public_key: str | None = None,
        revoked_signer_ids: frozenset[str] = frozenset(),
        seen_certificate_ids: MutableSet[str] | None = None,
    ):
        self.trusted_signer_public_key = trusted_signer_public_key
        self.trusted_recorder_public_key = trusted_recorder_public_key
        self.revoked_signer_ids = revoked_signer_ids
        self.seen_certificate_ids = seen_certificate_ids

    def verify(self, envelope: Mapping[str, Any]) -> DenialVerificationResult:
        try:
            if not isinstance(envelope, Mapping) or set(envelope) != self.ENVELOPE_FIELDS:
                raise ValidationError("denial certificate envelope fields are invalid")
            if envelope["algorithm"] != "Ed25519":
                raise ValidationError("denial certificate algorithm is invalid")
            public_key = serialization.load_pem_public_key(
                self.trusted_signer_public_key.encode("ascii")
            )
            if not isinstance(public_key, Ed25519PublicKey):
                raise ValidationError("trusted denial key is not Ed25519")
            signer_key_id = _key_id(public_key)
            embedded_key = serialization.load_pem_public_key(
                envelope["public_key_pem"].encode("ascii")
            )
            if not isinstance(embedded_key, Ed25519PublicKey) or _key_id(embedded_key) != signer_key_id:
                raise ValidationError("denial certificate signer is not trusted")
            if envelope["key_id"] != signer_key_id or signer_key_id in self.revoked_signer_ids:
                raise ValidationError("denial certificate signer is unknown or revoked")
            payload = envelope["certificate"]
            if not isinstance(payload, Mapping) or set(payload) != self.PAYLOAD_FIELDS:
                raise ValidationError("denial certificate payload fields are invalid")
            if payload["certificate_version"] != DENIAL_SCHEMA:
                raise ValidationError("denial certificate version is unsupported")
            if payload["signature_algorithm"] != "Ed25519" or payload["signer_key_id"] != signer_key_id:
                raise ValidationError("denial certificate signature metadata is invalid")
            if not isinstance(envelope["signature"], str) or not _SIGNATURE.fullmatch(envelope["signature"]):
                raise ValidationError("denial certificate signature is malformed")
            signature = base64.urlsafe_b64decode(envelope["signature"] + "==")
            public_key.verify(signature, canonical_bytes(payload))
            certificate_id = payload["certificate_id"]
            if not isinstance(certificate_id, str) or not _CERTIFICATE_ID.fullmatch(certificate_id):
                raise ValidationError("denial certificate ID is malformed")
            if payload["archival_status"] not in ARCHIVAL_STATES or payload["archival_status"] == "revoked":
                raise ValidationError("denial certificate archival status is invalid")
            effect_state = payload["effect_state"]
            if effect_state not in EFFECT_STATES:
                raise ValidationError("denial certificate effect state is invalid")
            expected_no_effect = True if effect_state in KNOWN_NO_EFFECT_STATES else (
                False if effect_state == "effect-committed-response-lost" else None
            )
            if payload["no_authorized_effect_committed"] is not expected_no_effect:
                raise ValidationError("denial certificate overstates the known effect outcome")
            for name in (
                "workload_identity_hash", "request_digest", "canonical_request_digest",
                "policy_digest", "policy_ceiling_digest", "provider_attestation_digest",
                "guardian_state_digest", "decay_state_digest", "evidence_chain_root",
            ):
                _sha(payload[name], name)
            _privacy_safe(payload["requested_authority"], "requested authority")
            _privacy_safe(payload["effective_authority"], "effective authority")
            recorder_key = envelope["recorder_public_key_pem"]
            receipt_verification_key = recorder_key
            if self.trusted_recorder_public_key is not None:
                trusted_recorder = serialization.load_pem_public_key(
                    self.trusted_recorder_public_key.encode("ascii")
                )
                embedded_recorder = serialization.load_pem_public_key(recorder_key.encode("ascii"))
                if (
                    not isinstance(trusted_recorder, Ed25519PublicKey)
                    or not isinstance(embedded_recorder, Ed25519PublicKey)
                    or _key_id(trusted_recorder) != _key_id(embedded_recorder)
                ):
                    raise ValidationError("denial evidence recorder is not trusted")
                receipt_verification_key = self.trusted_recorder_public_key
            receipt = envelope["recorder_receipt"]
            if not ExternalRecorder.verify_receipt(receipt, receipt_verification_key):
                raise ValidationError("denial evidence receipt is invalid")
            references = payload["relevant_evidence_references"]
            if not isinstance(references, list) or len(references) != 1:
                raise ValidationError("denial evidence reference is missing")
            reference = references[0]
            if not isinstance(reference, Mapping) or set(reference) != {
                "sequence", "event_hash", "event_type"
            }:
                raise ValidationError("denial evidence reference is malformed")
            receipt_payload = receipt["payload"]
            if (
                reference["event_type"] != "denial.evaluated"
                or reference["sequence"] != receipt_payload["sequence"]
                or reference["event_hash"] != receipt_payload["event_hash"]
                or reference["event_hash"] != payload["evidence_chain_root"]
            ):
                raise ValidationError("denial evidence is not linked to the recorded chain root")
            if self.seen_certificate_ids is not None:
                if certificate_id in self.seen_certificate_ids:
                    raise ValidationError("denial certificate ID was replayed")
                self.seen_certificate_ids.add(certificate_id)
            return DenialVerificationResult(True, "verified", certificate_id, effect_state)
        except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
            return DenialVerificationResult(False, str(exc))
