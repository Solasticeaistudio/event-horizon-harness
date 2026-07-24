from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable, Protocol

from .attestation import AttestationError, AttestationProvider
from .component_ids import (
    BEHAVIORAL_TRANSITION_GUARDIAN,
    EXECUTOR_ATTESTATION_GUARDIAN,
    LINEAGE_BUDGET_GUARDIAN,
    STATIC_POLICY_GUARDIAN,
)
from .models import ActionRequest, GuardianDecision
from .policy import StaticPolicy


class Guardian(Protocol):
    name: str
    def evaluate(self, request: ActionRequest) -> GuardianDecision: ...


@dataclass
class PolicyGuardian:
    policy: StaticPolicy
    name: str = STATIC_POLICY_GUARDIAN

    def evaluate(self, request: ActionRequest) -> GuardianDecision:
        return self.policy.evaluate(request)


@dataclass
class AttestationGuardian:
    provider: AttestationProvider
    name: str = EXECUTOR_ATTESTATION_GUARDIAN

    def evaluate(self, request: ActionRequest) -> GuardianDecision:
        try:
            evidence = dict(self.provider.verify_executor(
                request.executor_id,
                request.session_id,
                request.purpose,
            ))
        except AttestationError as exc:
            return GuardianDecision(self.name, False, str(exc))
        measurement = dict(evidence.get("measurements", {})).get("executor")
        if not measurement:
            return GuardianDecision(self.name, False, "verified evidence omitted executor measurement")
        if evidence.get("deviceId") != request.executor_id:
            return GuardianDecision(self.name, False, "verified device does not match requested executor")
        required = (
            "bundleDigest", "resultDigest", "verifierPolicyDigest", "keyId",
            "nonceContext", "nonceIssuedAt", "nonceExpiresAt",
        )
        if any(not evidence.get(name) for name in required):
            return GuardianDecision(self.name, False, "verified evidence omitted required binding")
        expected_nonce_context = {
            "deviceId": request.executor_id,
            "executorId": request.executor_id,
            "sessionId": request.session_id,
            "purpose": request.purpose,
        }
        if evidence["nonceContext"] != expected_nonce_context:
            return GuardianDecision(self.name, False, "verified nonce context does not match request")
        return GuardianDecision(
            self.name,
            True,
            "executor identity and measurement verified",
            {
                "device_id": evidence.get("deviceId"),
                "measurement": measurement,
                "bundle_digest": evidence.get("bundleDigest"),
                "attestation_result_digest": evidence.get("resultDigest"),
                "verifier_policy_digest": evidence.get("verifierPolicyDigest"),
                "method": evidence.get("method"),
                "trust_level": evidence.get("trustLevel"),
                "assurance_level": evidence.get("assuranceLevel"),
                "key_id": evidence.get("keyId"),
                "nonce_context": evidence.get("nonceContext"),
                "nonce_issued_at": evidence.get("nonceIssuedAt"),
                "nonce_expires_at": evidence.get("nonceExpiresAt"),
            },
        )


@dataclass
class LineageBudgetGuardian:
    max_requests_per_session: int = 8
    max_denials_per_session: int = 3
    name: str = LINEAGE_BUDGET_GUARDIAN
    _requests: dict[str, int] = field(default_factory=dict)
    _denials: dict[str, int] = field(default_factory=dict)

    def evaluate(self, request: ActionRequest) -> GuardianDecision:
        used = self._requests.get(request.session_id, 0)
        denied = self._denials.get(request.session_id, 0)
        if used >= self.max_requests_per_session:
            return GuardianDecision(self.name, False, "session request budget exhausted")
        if denied >= self.max_denials_per_session:
            return GuardianDecision(self.name, False, "session denial budget exhausted")
        self._requests[request.session_id] = used + 1
        return GuardianDecision(self.name, True, "lineage budget available", {"used": used + 1})

    def record_denial(self, session_id: str) -> None:
        self._denials[session_id] = self._denials.get(session_id, 0) + 1


@dataclass
class SequenceGuardian:
    suspicious_operations: frozenset[str] = frozenset({
        "shell.execute", "http.request", "package.install", "credential.read",
        "network.connect", "tool.register", "policy.modify"
    })
    name: str = BEHAVIORAL_TRANSITION_GUARDIAN

    def evaluate(self, request: ActionRequest) -> GuardianDecision:
        if request.operation in self.suspicious_operations:
            return GuardianDecision(self.name, False, "operation is a prohibited escape primitive")
        return GuardianDecision(self.name, True, "no prohibited transition detected")


@dataclass
class GuardianQuorum:
    guardians: Iterable[Guardian]

    def evaluate(self, request: ActionRequest) -> list[GuardianDecision]:
        decisions = [g.evaluate(request) for g in self.guardians]
        # Any veto blocks. Approvals cannot widen the static request.
        return decisions

    @staticmethod
    def allowed(decisions: Iterable[GuardianDecision]) -> bool:
        decisions = list(decisions)
        return bool(decisions) and all(decision.allowed for decision in decisions)
