from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .canonical import digest
from .models import ActionRequest, GuardianDecision


@dataclass(frozen=True)
class OperationRule:
    resources: frozenset[str]
    allowed_argument_keys: frozenset[str] = frozenset()
    max_output_bytes: int = 65536


@dataclass
class StaticPolicy:
    policy_id: str
    operations: Mapping[str, OperationRule]
    allowed_agents: frozenset[str]
    allowed_executors: frozenset[str]
    denied_argument_keys: frozenset[str] = field(default_factory=lambda: frozenset({
        "url", "uri", "host", "hostname", "ip", "port", "command", "shell",
        "token", "credential", "api_key", "authorization", "recipient"
    }))

    @property
    def policy_digest(self) -> str:
        payload = {
            "policy_id": self.policy_id,
            "allowed_agents": sorted(self.allowed_agents),
            "allowed_executors": sorted(self.allowed_executors),
            "denied_argument_keys": sorted(self.denied_argument_keys),
            "operations": {
                name: {
                    "resources": sorted(rule.resources),
                    "allowed_argument_keys": sorted(rule.allowed_argument_keys),
                    "max_output_bytes": rule.max_output_bytes,
                }
                for name, rule in sorted(self.operations.items())
            },
        }
        return digest(payload)

    def evaluate(self, request: ActionRequest) -> GuardianDecision:
        if request.agent_id not in self.allowed_agents:
            return GuardianDecision("cerberus", False, "agent is not authorized")
        if request.executor_id not in self.allowed_executors:
            return GuardianDecision("cerberus", False, "executor is not authorized")
        rule = self.operations.get(request.operation)
        if rule is None:
            return GuardianDecision("cerberus", False, "operation is deny-by-default")
        if request.resource_id not in rule.resources:
            return GuardianDecision("cerberus", False, "resource is outside the policy set")
        keys = set(request.arguments)
        forbidden = keys & self.denied_argument_keys
        if forbidden:
            return GuardianDecision("cerberus", False, f"forbidden argument keys: {sorted(forbidden)}")
        unknown = keys - rule.allowed_argument_keys
        if unknown:
            return GuardianDecision("cerberus", False, f"argument widening: {sorted(unknown)}")
        return GuardianDecision(
            "cerberus", True, "static policy permits exact request",
            {"max_output_bytes": rule.max_output_bytes, "policy_digest": self.policy_digest}
        )
