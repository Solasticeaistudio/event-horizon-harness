from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .broker import CapabilityBroker
from .guardians import GuardianQuorum, LineageBudgetGuardian
from .models import ActionRequest, IssuedCapability, ValidationError
from .policy import StaticPolicy
from .recorder import ExternalRecorder


class AuthorizationDenied(PermissionError):
    pass


@dataclass
class NeuralLinkZero:
    """The sole intent membrane. It has no execution authority."""

    policy: StaticPolicy
    quorum: GuardianQuorum
    broker: CapabilityBroker
    recorder: ExternalRecorder
    executor_measurements: Mapping[str, str]

    def request_capability(self, payload: Mapping[str, Any]) -> tuple[ActionRequest, IssuedCapability]:
        try:
            request = ActionRequest.from_dict(payload)
        except ValidationError as exc:
            self.recorder.append("request.rejected", {"reason": str(exc), "payload_digest_only": True})
            raise

        self.recorder.append("request.received", {
            "request_id": request.request_id,
            "session_id": request.session_id,
            "agent_id": request.agent_id,
            "operation": request.operation,
            "resource_id": request.resource_id,
            "executor_id": request.executor_id,
            "request_digest": request.request_digest,
        })

        decisions = self.quorum.evaluate(request)
        for decision in decisions:
            self.recorder.append("guardian.decision", {
                "request_id": request.request_id,
                "guardian": decision.guardian,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "evidence": dict(decision.evidence),
            })
        if not self.quorum.allowed(decisions):
            for guardian in self.quorum.guardians:
                if isinstance(guardian, LineageBudgetGuardian):
                    guardian.record_denial(request.session_id)
            self.recorder.append("request.denied", {"request_id": request.request_id})
            raise AuthorizationDenied("guardian veto")

        attestation_decision = next(d for d in decisions if d.guardian == "attestation")
        measurement = str(attestation_decision.evidence["measurement"])
        device_id = str(attestation_decision.evidence["device_id"])
        attestation_digest = str(attestation_decision.evidence["attestation_result_digest"])
        attestation_bundle_digest = str(attestation_decision.evidence["bundle_digest"])
        verifier_policy_digest = str(attestation_decision.evidence["verifier_policy_digest"])
        policy_decision = next(d for d in decisions if d.guardian == "cerberus")
        max_output_bytes = int(policy_decision.evidence["max_output_bytes"])
        capability = self.broker.issue(
            request,
            device_id=device_id,
            executor_measurement=measurement,
            attestation_digest=attestation_digest,
            attestation_bundle_digest=attestation_bundle_digest,
            verifier_policy_digest=verifier_policy_digest,
            policy_digest=self.policy.policy_digest,
            max_output_bytes=max_output_bytes,
        )
        self.recorder.append("capability.issued", {
            "request_id": request.request_id,
            "capability_id": capability.claims.capability_id,
            "claims_digest": request.request_digest,
            "expires_at": capability.claims.expires_at,
            "key_id": capability.key_id,
            "device_id": capability.claims.device_id,
            "executor_measurement": capability.claims.executor_measurement,
            "policy_digest": capability.claims.policy_digest,
            "request_digest": capability.claims.request_digest,
            "attestation_digest": capability.claims.attestation_digest,
            "attestation_bundle_digest": capability.claims.attestation_bundle_digest,
            "verifier_policy_digest": capability.claims.verifier_policy_digest,
        })
        return request, capability
