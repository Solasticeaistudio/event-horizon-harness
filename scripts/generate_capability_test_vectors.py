#!/usr/bin/env python3
"""Regenerate public capability vectors using a no-authority test-only key."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.broker import capability_key_id
from event_horizon.canonical import canonical_bytes, digest
from event_horizon.models import ActionRequest, CapabilityClaims, IssuedCapability
from capability_fixture_support import authority_context, verify_options


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "test-vectors"
# This deterministic seed is a public test fixture and possesses no authority.
TEST_SEED = hashlib.sha256(b"event-horizon-v0.4-public-capability-vector-key-no-authority").digest()
ISSUED_AT = 1_700_000_000_000


def main() -> int:
    private_key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    public_key = private_key.public_key()
    key_id = capability_key_id(public_key)
    request = {
        "request_id": "vector-request",
        "session_id": "vector-session",
        "agent_id": "attacker-agent",
        "operation": "object.read",
        "resource_id": "target-source",
        "executor_id": "exec-1",
        "arguments": {"length": 10, "offset": 0},
        "purpose": "public capability vector",
    }
    authority = authority_context(ActionRequest.from_dict(request), ISSUED_AT / 1000)
    context = verify_options(authority)
    trust = authority["trust_state"]
    compiled = authority["compiled_ceiling"]
    claims = CapabilityClaims(
        capability_id="cap_0123456789abcdef01234567",
        issued_at=ISSUED_AT,
        expires_at=ISSUED_AT + 60_000,
        session_id=request["session_id"],
        agent_id=request["agent_id"],
        executor_id=request["executor_id"],
        device_id=context["device_id"],
        executor_measurement=context["executor_measurement"],
        attestation_digest=trust.attestation_digest,
        attestation_bundle_digest=trust.bundle_digest,
        verifier_policy_digest=trust.verifier_policy_digest,
        task_id=compiled.task_id,
        task_fingerprint=compiled.task_fingerprint,
        tenant=compiled.tenant,
        environment=compiled.environment,
        audience="effect-executor",
        requested_trust=trust.requested_trust,
        provider_attested_trust=trust.provider_attested_trust,
        effective_trust=trust.effective_trust,
        signed_trust_constraint=compiled.required_trust_tier,
        attestation_method=trust.method,
        attestation_key_id=trust.key_id,
        compiled_ceiling=compiled.to_dict(),
        compiled_ceiling_digest=compiled.compiled_digest,
        guardian_state_digest=authority["guardian_state_digest"],
        decay_profile_id=compiled.decay_profile,
        decay_profile_version="v1",
        initial_authority_digest=compiled.compiled_digest,
        operation=request["operation"],
        resource_id=request["resource_id"],
        arguments_digest=digest(request["arguments"]),
        request_digest=digest(request),
        max_output_bytes=4096,
        invocation_limit=1,
        signer_key_id=key_id,
        policy_digest=authority["policy_digest"],
    )
    signature = base64.urlsafe_b64encode(
        private_key.sign(canonical_bytes(claims.to_dict()))
    ).rstrip(b"=").decode("ascii")
    capability = IssuedCapability(claims, signature, key_id).to_dict()
    base = {
        "schema": "event-horizon.capability-test-vector.v1",
        "public_key_pem": public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii"),
        "request": request,
        "capability": capability,
        "context": context,
        "verification_time": ISSUED_AT / 1000,
        "preconsume": False,
    }

    vectors: dict[str, dict] = {}

    def vector(name: str, description: str, valid: bool, reason: str) -> dict:
        value = copy.deepcopy(base)
        value["description"] = description
        value["expected"] = {"valid": valid, "reason": reason}
        vectors[name] = value
        return value

    vector("valid-capability.json", "Valid exact one-use capability.", True, "accepted")
    vector("modified-arguments.json", "Arguments changed after approval.", False, "arguments_digest")["request"]["arguments"]["length"] = 11
    vector("wrong-executor.json", "Capability transferred to a different executor.", False, "executor_id")["request"]["executor_id"] = "exec-2"
    vector("wrong-measurement.json", "Runtime executor measurement differs from the signed claim.", False, "executor_measurement")["context"]["executor_measurement"] = "9" * 64
    vector("expired-capability.json", "Verification occurs at the exclusive expiration boundary.", False, "capability expired")["verification_time"] = (ISSUED_AT + 60_000) / 1000
    vector("replayed-capability.json", "The same verifier consumes the capability before the tested attempt.", False, "capability replay")["preconsume"] = True
    vector("unknown-field.json", "Unknown capability envelope field.", False, "capability envelope fields are invalid")["capability"]["unknown"] = True
    vector("invalid-signature.json", "Canonical-length but invalid Ed25519 signature.", False, "invalid capability signature")["capability"]["signature"] = "A" * 86

    OUTPUT.mkdir(exist_ok=True)
    for name, value in vectors.items():
        (OUTPUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
