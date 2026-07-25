from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Protocol

from .attestation import AttestationError, AttestationProvider
from .component_ids import (
    BEHAVIORAL_TRANSITION_GUARDIAN,
    EXECUTOR_ATTESTATION_GUARDIAN,
    LINEAGE_BUDGET_GUARDIAN,
    STATIC_POLICY_GUARDIAN,
    REQUIRED_GUARDIANS,
)
from .models import ActionRequest, GuardianDecision
from .policy import StaticPolicy
from .task_policy import ProviderTrustState


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
            return GuardianDecision(self.name, False, str(exc), request_digest=request.request_digest)
        measurement = dict(evidence.get("measurements", {})).get("executor")
        if not measurement:
            return GuardianDecision(self.name, False, "verified evidence omitted executor measurement", request_digest=request.request_digest)
        if evidence.get("deviceId") != request.executor_id:
            return GuardianDecision(self.name, False, "verified device does not match requested executor", request_digest=request.request_digest)
        required = (
            "bundleDigest", "resultDigest", "verifierPolicyDigest", "keyId",
            "nonceContext", "nonceIssuedAt", "nonceExpiresAt",
        )
        if any(not evidence.get(name) for name in required):
            return GuardianDecision(self.name, False, "verified evidence omitted required binding", request_digest=request.request_digest)
        expected_nonce_context = {
            "deviceId": request.executor_id,
            "executorId": request.executor_id,
            "sessionId": request.session_id,
            "purpose": request.purpose,
        }
        if evidence["nonceContext"] != expected_nonce_context:
            return GuardianDecision(self.name, False, "verified nonce context does not match request", request_digest=request.request_digest)
        try:
            trust_state = ProviderTrustState.from_attestation(evidence)
        except ValueError as exc:
            return GuardianDecision(
                self.name,
                False,
                f"provider trust state is invalid: {exc}",
                request_digest=request.request_digest,
            )
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
                "provider_trust_state": trust_state.to_dict(),
                "attestation_result": dict(evidence),
            },
            request.request_digest,
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
            return GuardianDecision(self.name, False, "session request budget exhausted", request_digest=request.request_digest)
        if denied >= self.max_denials_per_session:
            return GuardianDecision(self.name, False, "session denial budget exhausted", request_digest=request.request_digest)
        self._requests[request.session_id] = used + 1
        return GuardianDecision(self.name, True, "lineage budget available", {"used": used + 1}, request.request_digest)

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
            return GuardianDecision(self.name, False, "operation is a prohibited escape primitive", request_digest=request.request_digest)
        return GuardianDecision(self.name, True, "no prohibited transition detected", request_digest=request.request_digest)


@dataclass
class GuardianQuorum:
    guardians: Iterable[Guardian]
    guardian_timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        self.guardians = list(self.guardians)
        if not 0 < self.guardian_timeout_seconds <= 30:
            raise ValueError("guardian timeout must be greater than zero and at most 30 seconds")

    def _evaluate_one(self, guardian: Guardian, request: ActionRequest) -> GuardianDecision:
        guardian_name = getattr(guardian, "name", "malformed-guardian")
        outcome: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

        def invoke() -> None:
            try:
                outcome.put((True, guardian.evaluate(request)), block=False)
            except Exception as exc:
                outcome.put((False, exc), block=False)

        worker = threading.Thread(target=invoke, daemon=True, name=f"guardian-{guardian_name}")
        worker.start()
        worker.join(self.guardian_timeout_seconds)
        if worker.is_alive():
            return GuardianDecision(
                guardian_name,
                False,
                "guardian timed out",
                request_digest=request.request_digest,
            )
        try:
            completed, value = outcome.get_nowait()
        except queue.Empty:
            return GuardianDecision(
                guardian_name,
                False,
                "guardian returned no decision",
                request_digest=request.request_digest,
            )
        if not completed:
            return GuardianDecision(
                guardian_name,
                False,
                "guardian failed closed",
                request_digest=request.request_digest,
            )
        if (
            not isinstance(value, GuardianDecision)
            or value.guardian != guardian_name
            or type(value.allowed) is not bool
            or not isinstance(value.reason, str)
            or not value.reason
            or not isinstance(value.evidence, Mapping)
            or value.request_digest != request.request_digest
        ):
            return GuardianDecision(
                guardian_name,
                False,
                "guardian response binding or schema mismatch",
                request_digest=request.request_digest,
            )
        return value

    def _expected_policy_digest(self) -> str | None:
        for guardian in self.guardians:
            if getattr(guardian, "name", None) == STATIC_POLICY_GUARDIAN:
                policy = getattr(guardian, "policy", None)
                candidate = getattr(policy, "policy_digest", None)
                if isinstance(candidate, str):
                    return candidate
        return None

    def evaluate(self, request: ActionRequest) -> list[GuardianDecision]:
        decisions = [self._evaluate_one(guardian, request) for guardian in list(self.guardians)]
        present = {decision.guardian for decision in decisions}
        for missing in sorted(REQUIRED_GUARDIANS - present):
            decisions.append(GuardianDecision(
                missing,
                False,
                "required guardian is unavailable",
                request_digest=request.request_digest,
            ))

        expected_policy_digest = self._expected_policy_digest()
        seen: set[str] = set()
        for index, decision in enumerate(decisions):
            reported_policy = decision.evidence.get("policy_digest")
            inconsistent_policy = (
                decision.guardian == STATIC_POLICY_GUARDIAN
                and decision.allowed
                and (expected_policy_digest is None or reported_policy != expected_policy_digest)
            ) or (
                reported_policy is not None
                and expected_policy_digest is not None
                and reported_policy != expected_policy_digest
            )
            if decision.guardian in seen or inconsistent_policy:
                decisions[index] = GuardianDecision(
                    decision.guardian,
                    False,
                    "duplicate guardian or inconsistent policy version",
                    request_digest=request.request_digest,
                )
            seen.add(decision.guardian)
        # Any veto blocks. Approvals cannot widen the static request.
        return decisions

    def allowed(self, decisions: Iterable[GuardianDecision]) -> bool:
        decisions = list(decisions)
        names = [decision.guardian for decision in decisions]
        request_digests = {decision.request_digest for decision in decisions}
        expected_policy_digest = self._expected_policy_digest()
        static_decisions = [
            decision for decision in decisions if decision.guardian == STATIC_POLICY_GUARDIAN
        ]
        return (
            bool(decisions)
            and len(names) == len(set(names))
            and REQUIRED_GUARDIANS.issubset(names)
            and len(request_digests) == 1
            and all(decision.allowed for decision in decisions)
            and len(static_decisions) == 1
            and expected_policy_digest is not None
            and static_decisions[0].evidence.get("policy_digest") == expected_policy_digest
            and all(
                decision.evidence.get("policy_digest", expected_policy_digest) == expected_policy_digest
                for decision in decisions
            )
        )
