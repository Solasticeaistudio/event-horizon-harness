from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Mapping

from .broker import CapabilityBroker
from .canonical import digest
from .component_ids import EXECUTOR_ATTESTATION_GUARDIAN, STATIC_POLICY_GUARDIAN
from .guardians import GuardianQuorum, LineageBudgetGuardian
from .models import ActionRequest, IssuedCapability, ValidationError
from .policy import StaticPolicy
from .recorder import ExternalRecorder
from .task_policy import (
    ProviderTrustState,
    TaskPolicySynthesizer,
    TrustedPolicyCompiler,
    task_description_for_request,
)


class AuthorizationDenied(PermissionError):
    pass


@dataclass
class IntentCanonicalizer:
    """The sole intent membrane. It has no execution authority."""

    policy: StaticPolicy
    quorum: GuardianQuorum
    broker: CapabilityBroker
    recorder: ExternalRecorder
    executor_measurements: Mapping[str, str]
    policy_synthesizer: TaskPolicySynthesizer
    policy_compiler: TrustedPolicyCompiler
    tool_actions: Mapping[str, frozenset[str]]

    def request_capability(
        self,
        payload: Mapping[str, Any],
    ) -> tuple[ActionRequest, IssuedCapability, dict[str, Any]]:
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

        approved_request_digest = request.request_digest
        decisions = self.quorum.evaluate(request)
        if request.request_digest != approved_request_digest:
            self.recorder.append("request.denied", {"request_id": request.request_id})
            raise AuthorizationDenied("request changed during guardian evaluation")
        for decision in decisions:
            self.recorder.append("guardian.decision", {
                "request_id": request.request_id,
                "guardian": decision.guardian,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "evidence": dict(decision.evidence),
                "request_digest": decision.request_digest,
            })
        if not self.quorum.allowed(decisions):
            for guardian in self.quorum.guardians:
                if isinstance(guardian, LineageBudgetGuardian):
                    guardian.record_denial(request.session_id)
            self.recorder.append("request.denied", {"request_id": request.request_id})
            raise AuthorizationDenied("guardian veto")

        attestation_decision = next(
            d for d in decisions if d.guardian == EXECUTOR_ATTESTATION_GUARDIAN
        )
        measurement = str(attestation_decision.evidence["measurement"])
        device_id = str(attestation_decision.evidence["device_id"])
        trust_state = ProviderTrustState.from_dict(
            attestation_decision.evidence["provider_trust_state"]
        )
        attestation_result = dict(attestation_decision.evidence["attestation_result"])
        task = task_description_for_request(
            request,
            self.policy,
            trust_state,
            self.tool_actions,
        )
        candidate = self.policy_synthesizer.synthesize(task)
        compiled_ceiling = self.policy_compiler.compile(
            task,
            candidate,
            now_ms=int(time.time() * 1000),
        )
        policy_decision = next(d for d in decisions if d.guardian == STATIC_POLICY_GUARDIAN)
        max_output_bytes = int(policy_decision.evidence["max_output_bytes"])
        capability = self.broker.issue(
            request,
            device_id=device_id,
            executor_measurement=measurement,
            trust_state=trust_state,
            compiled_ceiling=compiled_ceiling,
            policy_digest=self.policy.policy_digest,
            max_output_bytes=max_output_bytes,
            guardian_state_digest=digest([
                {
                    "guardian": decision.guardian,
                    "allowed": decision.allowed,
                    "reason": decision.reason,
                    "evidence": dict(decision.evidence),
                    "request_digest": decision.request_digest,
                }
                for decision in decisions
            ]),
        )
        self.recorder.append("capability.issued", {
            "request_id": request.request_id,
            "capability_id": capability.claims.capability_id,
            "claims_digest": digest(capability.claims.to_dict()),
            "expires_at": capability.claims.expires_at,
            "key_id": capability.key_id,
            "device_id": capability.claims.device_id,
            "executor_measurement": capability.claims.executor_measurement,
            "policy_digest": capability.claims.policy_digest,
            "request_digest": capability.claims.request_digest,
            "attestation_digest": capability.claims.attestation_digest,
            "attestation_bundle_digest": capability.claims.attestation_bundle_digest,
            "verifier_policy_digest": capability.claims.verifier_policy_digest,
            "task_fingerprint": capability.claims.task_fingerprint,
            "compiled_ceiling_digest": capability.claims.compiled_ceiling_digest,
            "provider_trust": capability.claims.provider_attested_trust,
        })
        return request, capability, attestation_result
