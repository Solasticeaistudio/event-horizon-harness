from __future__ import annotations

import queue
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol, Sequence

from .canonical import canonical_bytes, digest
from .models import ActionRequest, ValidationError
from .policy import StaticPolicy


TRUST_ORDER = {"simulated": 0, "software": 1, "hardware": 2}
SYNTHESIS_MODES = {"static", "rule", "model", "shadow", "evaluation"}
FALLBACK_MODES = {"deny", "clarify", "minimal-read-only"}
_MAX_COLLECTION = 256
ATTESTATION_METHOD_TRUST = {
    "simulator": "simulated",
    "static-development": "software",
    "tpm2": "hardware",
}


class PolicySynthesisError(RuntimeError):
    """A policy proposal could not be produced safely."""


class PolicyCompilationError(PermissionError):
    """A candidate ceiling could not become hard-enforceable authority."""


def _timestamp_ms(value: Any, label: str) -> int:
    text = _text(value, label, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{label} must include a timezone")
    return int(parsed.astimezone(timezone.utc).timestamp() * 1000)


def _text(value: Any, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ValidationError(f"{label} must be a non-empty string <= {maximum} UTF-8 bytes")
    canonical_bytes(value)
    return value


def _optional_text(value: Any, label: str, maximum: int = 256) -> str | None:
    if value is None:
        return None
    return _text(value, label, maximum)


def _strings(values: Sequence[Any], label: str, *, maximum: int = _MAX_COLLECTION) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or len(values) > maximum:
        raise ValidationError(f"{label} must be a bounded array")
    normalized = tuple(_text(value, f"{label} item") for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValidationError(f"{label} contains duplicates")
    return tuple(sorted(normalized))


def _nonnegative(value: Any, label: str, *, maximum: int = 2**53 - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValidationError(f"{label} must be a non-negative bounded integer")
    return value


def _positive(value: Any, label: str, *, maximum: int = 2**53 - 1) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise ValidationError(f"{label} must be a positive bounded integer")
    return value


def _digest(value: Any, label: str) -> str:
    normalized = _text(value, label, 64)
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise ValidationError(f"{label} must be a lowercase SHA-256 digest")
    return normalized


def _mapping_of_string_arrays(value: Any, label: str) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, Mapping) or len(value) > _MAX_COLLECTION:
        raise ValidationError(f"{label} must be a bounded object")
    normalized: dict[str, tuple[str, ...]] = {}
    for key, items in value.items():
        normalized[_text(key, f"{label} key")] = _strings(items, f"{label}.{key}")
    return dict(sorted(normalized.items()))


@dataclass(frozen=True)
class ProviderTrustState:
    requested_trust: str
    observed_trust: str
    provider_attested_trust: str
    effective_trust: str
    method: str
    key_id: str
    attestation_digest: str
    bundle_digest: str
    verifier_policy_digest: str
    verified_at_ms: int
    expires_at_ms: int

    FIELDS = frozenset({
        "requested_trust", "observed_trust", "provider_attested_trust", "effective_trust",
        "method", "key_id", "attestation_digest", "bundle_digest", "verifier_policy_digest",
        "verified_at_ms", "expires_at_ms",
    })

    def __post_init__(self) -> None:
        for name in (
            "requested_trust", "observed_trust", "provider_attested_trust", "effective_trust",
        ):
            value = _text(getattr(self, name), name, 32)
            if value not in TRUST_ORDER:
                raise ValidationError(f"{name} is not a supported trust tier")
        _text(self.method, "attestation method", 64)
        _text(self.key_id, "attestation key ID", 128)
        for name in ("attestation_digest", "bundle_digest", "verifier_policy_digest"):
            _digest(getattr(self, name), name)
        _nonnegative(self.verified_at_ms, "trust verification time")
        _positive(self.expires_at_ms, "trust expiration time")
        if self.expires_at_ms <= self.verified_at_ms:
            raise ValidationError("provider trust expiration must follow verification")
        authoritative = min(
            TRUST_ORDER[self.observed_trust],
            TRUST_ORDER[self.provider_attested_trust],
        )
        if TRUST_ORDER[self.effective_trust] != authoritative:
            raise ValidationError("effective trust must equal the conservative observed/provider intersection")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in sorted(self.FIELDS)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProviderTrustState":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ValidationError("provider trust state fields are invalid")
        return cls(**dict(value))

    @classmethod
    def from_attestation(
        cls,
        value: Mapping[str, Any],
        *,
        requested_trust: str = "simulated",
    ) -> "ProviderTrustState":
        if not isinstance(value, Mapping):
            raise ValidationError("attestation result must be an object")
        required = {
            "valid", "deviceId", "method", "trustLevel", "keyId", "measurements",
            "bundleDigest", "verifiedAt", "verifierPolicyDigest", "resultDigest",
            "nonceExpiresAt",
        }
        if not required.issubset(value):
            raise ValidationError("attestation result omitted authoritative trust fields")
        if value["valid"] is not True:
            raise ValidationError("attestation result is not valid")
        unsigned = dict(value)
        claimed_digest = unsigned.pop("resultDigest")
        if digest(unsigned) != claimed_digest:
            raise ValidationError("attestation result digest mismatch")
        method = _text(value["method"], "attestation method", 64)
        provider_trust = _text(value["trustLevel"], "provider trust", 32)
        expected_trust = ATTESTATION_METHOD_TRUST.get(method)
        if expected_trust is None:
            raise ValidationError("attestation method is not registered")
        if provider_trust != expected_trust:
            raise ValidationError("attestation method and provider trust are contradictory")
        verified_at = _timestamp_ms(value["verifiedAt"], "attestation verification time")
        expires_at = _timestamp_ms(value["nonceExpiresAt"], "attestation expiration time")
        return cls(
            requested_trust=requested_trust,
            observed_trust=provider_trust,
            provider_attested_trust=provider_trust,
            effective_trust=provider_trust,
            method=method,
            key_id=_text(value["keyId"], "attestation key ID", 128),
            attestation_digest=_digest(claimed_digest, "attestation result digest"),
            bundle_digest=_digest(value["bundleDigest"], "attestation bundle digest"),
            verifier_policy_digest=_digest(
                value["verifierPolicyDigest"], "attestation verifier policy digest"
            ),
            verified_at_ms=verified_at,
            expires_at_ms=expires_at,
        )


@dataclass(frozen=True)
class TaskDescription:
    task_id: str
    requesting_subject: str
    workload_identity: str
    natural_language_task: str
    task_type: str | None
    tenant: str
    environment: str
    available_tools: tuple[str, ...]
    available_resources: tuple[str, ...]
    data_classification: str
    user_approved_constraints: Mapping[str, Any]
    global_policy_version: str
    provider_attested_trust: ProviderTrustState
    previous_approved_task_templates: tuple[str, ...] = ()
    approved_historical_traces: tuple[str, ...] = ()
    requested_completion_deadline_ms: int = 0
    human_approval_requirements: tuple[str, ...] = ()

    FIELDS = frozenset({
        "task_id", "requesting_subject", "workload_identity", "natural_language_task",
        "task_type", "tenant", "environment", "available_tools", "available_resources",
        "data_classification", "user_approved_constraints", "global_policy_version",
        "provider_attested_trust", "previous_approved_task_templates",
        "approved_historical_traces", "requested_completion_deadline_ms",
        "human_approval_requirements",
    })

    def __post_init__(self) -> None:
        _text(self.task_id, "task ID")
        _text(self.requesting_subject, "requesting subject")
        _text(self.workload_identity, "workload identity")
        _text(self.natural_language_task, "natural-language task", 4096)
        _optional_text(self.task_type, "task type")
        _text(self.tenant, "tenant")
        _text(self.environment, "environment")
        object.__setattr__(self, "available_tools", _strings(self.available_tools, "available tools"))
        object.__setattr__(self, "available_resources", _strings(self.available_resources, "available resources"))
        _text(self.data_classification, "data classification", 64)
        if not isinstance(self.user_approved_constraints, Mapping):
            raise ValidationError("user-approved constraints must be an object")
        canonical_bytes(self.user_approved_constraints)
        object.__setattr__(
            self,
            "user_approved_constraints",
            dict(sorted(self.user_approved_constraints.items())),
        )
        _text(self.global_policy_version, "global policy version")
        if not isinstance(self.provider_attested_trust, ProviderTrustState):
            raise ValidationError("task requires provider-derived trust state")
        object.__setattr__(
            self,
            "previous_approved_task_templates",
            _strings(self.previous_approved_task_templates, "approved task templates"),
        )
        object.__setattr__(
            self,
            "approved_historical_traces",
            tuple(_digest(item, "approved historical trace digest") for item in self.approved_historical_traces),
        )
        _positive(self.requested_completion_deadline_ms, "task completion deadline")
        object.__setattr__(
            self,
            "human_approval_requirements",
            _strings(self.human_approval_requirements, "human approval requirements"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "requesting_subject": self.requesting_subject,
            "workload_identity": self.workload_identity,
            "natural_language_task": self.natural_language_task,
            "task_type": self.task_type,
            "tenant": self.tenant,
            "environment": self.environment,
            "available_tools": list(self.available_tools),
            "available_resources": list(self.available_resources),
            "data_classification": self.data_classification,
            "user_approved_constraints": dict(self.user_approved_constraints),
            "global_policy_version": self.global_policy_version,
            "provider_attested_trust": self.provider_attested_trust.to_dict(),
            "previous_approved_task_templates": list(self.previous_approved_task_templates),
            "approved_historical_traces": list(self.approved_historical_traces),
            "requested_completion_deadline_ms": self.requested_completion_deadline_ms,
            "human_approval_requirements": list(self.human_approval_requirements),
        }

    @property
    def task_fingerprint(self) -> str:
        return digest(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TaskDescription":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ValidationError("task description fields are invalid")
        payload = dict(value)
        payload["provider_attested_trust"] = ProviderTrustState.from_dict(
            payload["provider_attested_trust"]
        )
        payload["available_tools"] = tuple(payload["available_tools"])
        payload["available_resources"] = tuple(payload["available_resources"])
        payload["previous_approved_task_templates"] = tuple(
            payload["previous_approved_task_templates"]
        )
        payload["approved_historical_traces"] = tuple(payload["approved_historical_traces"])
        payload["human_approval_requirements"] = tuple(payload["human_approval_requirements"])
        return cls(**payload)


def task_description_for_request(
    request: ActionRequest,
    policy: StaticPolicy,
    trust: ProviderTrustState,
    tool_actions: Mapping[str, frozenset[str]],
    *,
    tenant: str = "default",
    environment: str = "synthetic",
    task_type: str | None = None,
) -> TaskDescription:
    """Build the bounded trusted input around an untrusted action request.

    Natural-language purpose text participates in the fingerprint but does not
    select tools directly. The structured task type is selected by trusted code.
    """
    if task_type is None:
        task_type = {
            "object.read": "summarization",
            "compute.run": "read-only-analysis",
            "deployment.apply": "deployment",
        }.get(request.operation)
    resources = sorted({resource for rule in policy.operations.values() for resource in rule.resources})
    return TaskDescription(
        task_id=request.request_id,
        requesting_subject=request.agent_id,
        workload_identity=request.executor_id,
        natural_language_task=request.purpose or "No natural-language purpose supplied.",
        task_type=task_type,
        tenant=tenant,
        environment=environment,
        available_tools=tuple(sorted(tool_actions)),
        available_resources=tuple(resources),
        data_classification="internal",
        user_approved_constraints={
            "requested_action": request.operation,
            "requested_resource": request.resource_id,
            "requested_argument_keys": sorted(request.arguments),
        },
        global_policy_version=policy.policy_id,
        provider_attested_trust=trust,
        requested_completion_deadline_ms=trust.expires_at_ms,
    )


@dataclass(frozen=True)
class CandidateTaskPolicyCeiling:
    ceiling_id: str
    task_id: str
    task_fingerprint: str
    synthesizer_version: str
    model_version: str
    policy_version: str
    confidence_bps: int
    tools: tuple[str, ...]
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    action_resources: Mapping[str, tuple[str, ...]]
    argument_constraints: Mapping[str, tuple[str, ...]]
    network_destinations: tuple[str, ...]
    data_classes: tuple[str, ...]
    maximum_read_bytes: int
    maximum_write_bytes: int
    maximum_calls: int
    maximum_parallelism: int
    maximum_duration_seconds: int
    required_trust_tier: str
    required_attestations: tuple[str, ...]
    human_approval_gates: tuple[str, ...]
    decay_profile: str
    rationale_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    fallback_used: bool
    shadow_only: bool = False

    FIELDS = frozenset({
        "ceiling_id", "task_id", "task_fingerprint", "synthesizer_version", "model_version",
        "policy_version", "confidence_bps", "tools", "actions", "resources",
        "action_resources", "argument_constraints", "network_destinations", "data_classes",
        "maximum_read_bytes", "maximum_write_bytes", "maximum_calls", "maximum_parallelism",
        "maximum_duration_seconds", "required_trust_tier", "required_attestations",
        "human_approval_gates", "decay_profile", "rationale_codes", "evidence_refs",
        "fallback_used", "shadow_only",
    })

    def __post_init__(self) -> None:
        if not isinstance(self.ceiling_id, str) or not self.ceiling_id.startswith("ceil_"):
            raise ValidationError("candidate ceiling ID is malformed")
        _text(self.task_id, "candidate task ID")
        _digest(self.task_fingerprint, "task fingerprint")
        _text(self.synthesizer_version, "synthesizer version")
        _text(self.model_version, "model version")
        _text(self.policy_version, "candidate policy version")
        _nonnegative(self.confidence_bps, "candidate confidence", maximum=10_000)
        for name in (
            "tools", "actions", "resources", "network_destinations", "data_classes",
            "required_attestations", "human_approval_gates", "rationale_codes", "evidence_refs",
        ):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        object.__setattr__(
            self,
            "action_resources",
            _mapping_of_string_arrays(self.action_resources, "action resources"),
        )
        object.__setattr__(
            self,
            "argument_constraints",
            _mapping_of_string_arrays(self.argument_constraints, "argument constraints"),
        )
        for name in (
            "maximum_read_bytes", "maximum_write_bytes", "maximum_calls",
            "maximum_parallelism", "maximum_duration_seconds",
        ):
            _nonnegative(getattr(self, name), name)
        if self.required_trust_tier not in TRUST_ORDER:
            raise ValidationError("candidate required trust tier is invalid")
        _text(self.decay_profile, "decay profile")
        if type(self.fallback_used) is not bool or type(self.shadow_only) is not bool:
            raise ValidationError("candidate mode flags must be booleans")
        if set(self.action_resources) - set(self.actions):
            raise ValidationError("candidate action-resource constraints name an undeclared action")
        if set(self.argument_constraints) - set(self.actions):
            raise ValidationError("candidate argument constraints name an undeclared action")
        referenced_resources = {
            resource for values in self.action_resources.values() for resource in values
        }
        if not referenced_resources.issubset(self.resources):
            raise ValidationError("candidate action-resource constraints name an undeclared resource")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ceiling_id": self.ceiling_id,
            "task_id": self.task_id,
            "task_fingerprint": self.task_fingerprint,
            "synthesizer_version": self.synthesizer_version,
            "model_version": self.model_version,
            "policy_version": self.policy_version,
            "confidence_bps": self.confidence_bps,
            "tools": list(self.tools),
            "actions": list(self.actions),
            "resources": list(self.resources),
            "action_resources": {key: list(values) for key, values in self.action_resources.items()},
            "argument_constraints": {
                key: list(values) for key, values in self.argument_constraints.items()
            },
            "network_destinations": list(self.network_destinations),
            "data_classes": list(self.data_classes),
            "maximum_read_bytes": self.maximum_read_bytes,
            "maximum_write_bytes": self.maximum_write_bytes,
            "maximum_calls": self.maximum_calls,
            "maximum_parallelism": self.maximum_parallelism,
            "maximum_duration_seconds": self.maximum_duration_seconds,
            "required_trust_tier": self.required_trust_tier,
            "required_attestations": list(self.required_attestations),
            "human_approval_gates": list(self.human_approval_gates),
            "decay_profile": self.decay_profile,
            "rationale_codes": list(self.rationale_codes),
            "evidence_refs": list(self.evidence_refs),
            "fallback_used": self.fallback_used,
            "shadow_only": self.shadow_only,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CandidateTaskPolicyCeiling":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ValidationError("candidate ceiling fields are invalid")
        payload = dict(value)
        for name in (
            "tools", "actions", "resources", "network_destinations", "data_classes",
            "required_attestations", "human_approval_gates", "rationale_codes", "evidence_refs",
        ):
            payload[name] = tuple(payload[name])
        payload["action_resources"] = {
            key: tuple(items) for key, items in payload["action_resources"].items()
        }
        payload["argument_constraints"] = {
            key: tuple(items) for key, items in payload["argument_constraints"].items()
        }
        return cls(**payload)


@dataclass(frozen=True)
class PolicyTemplate:
    task_type: str
    tools: tuple[str, ...]
    actions: tuple[str, ...]
    action_resources: Mapping[str, tuple[str, ...]]
    argument_constraints: Mapping[str, tuple[str, ...]]
    data_classes: tuple[str, ...]
    maximum_read_bytes: int
    maximum_write_bytes: int
    maximum_calls: int
    maximum_parallelism: int
    maximum_duration_seconds: int
    required_trust_tier: str = "simulated"
    required_attestations: tuple[str, ...] = ("executor",)
    human_approval_gates: tuple[str, ...] = ()
    network_destinations: tuple[str, ...] = ()
    decay_profile: str = "short-lived-default"


class PolicyProposalModel(Protocol):
    version: str

    def propose(self, task: TaskDescription) -> Mapping[str, Any]: ...


def _candidate_id(payload: Mapping[str, Any]) -> str:
    return f"ceil_{digest(payload)[:24]}"


@dataclass
class TaskPolicySynthesizer:
    templates: Mapping[str, PolicyTemplate]
    mode: str = "static"
    synthesizer_version: str = "task-policy-synthesizer-v1"
    model: PolicyProposalModel | None = None
    model_timeout_seconds: float = 2.0
    minimum_confidence_bps: int = 7_000
    fallback_mode: str = "deny"
    dangerous_tools: frozenset[str] = frozenset({
        "shell", "deployment", "network", "credential", "package-manager",
    })

    def __post_init__(self) -> None:
        if self.mode not in SYNTHESIS_MODES:
            raise ValueError("unsupported policy synthesis mode")
        if self.fallback_mode not in FALLBACK_MODES:
            raise ValueError("unsupported policy fallback mode")
        if not 0 <= self.minimum_confidence_bps <= 10_000:
            raise ValueError("policy confidence threshold is invalid")
        if not 0 < self.model_timeout_seconds <= 30:
            raise ValueError("policy model timeout is invalid")

    def _fallback(self, task: TaskDescription, reason: str, *, shadow_only: bool = False) -> CandidateTaskPolicyCeiling:
        tools: tuple[str, ...] = ()
        actions: tuple[str, ...] = ()
        resources: tuple[str, ...] = ()
        action_resources: dict[str, tuple[str, ...]] = {}
        argument_constraints: dict[str, tuple[str, ...]] = {}
        gates = tuple(sorted({*task.human_approval_requirements, "clarification-required"}))
        if self.fallback_mode == "minimal-read-only":
            read_template = self.templates.get("read-only-analysis")
            if read_template is not None:
                tools = tuple(tool for tool in read_template.tools if tool in task.available_tools)
                actions = tuple(action for action in read_template.actions)
                action_resources = {
                    action: tuple(
                        resource
                        for resource in read_template.action_resources.get(action, ())
                        if resource in task.available_resources
                    )
                    for action in actions
                }
                resources = tuple(sorted({item for values in action_resources.values() for item in values}))
                argument_constraints = {
                    action: tuple(read_template.argument_constraints.get(action, ()))
                    for action in actions
                }
        payload = {
            "task_id": task.task_id,
            "task_fingerprint": task.task_fingerprint,
            "reason": reason,
            "fallback_mode": self.fallback_mode,
            "shadow_only": shadow_only,
        }
        return CandidateTaskPolicyCeiling(
            ceiling_id=_candidate_id(payload),
            task_id=task.task_id,
            task_fingerprint=task.task_fingerprint,
            synthesizer_version=self.synthesizer_version,
            model_version="none",
            policy_version=task.global_policy_version,
            confidence_bps=0,
            tools=tools,
            actions=actions,
            resources=resources,
            action_resources=action_resources,
            argument_constraints=argument_constraints,
            network_destinations=(),
            data_classes=(),
            maximum_read_bytes=0,
            maximum_write_bytes=0,
            maximum_calls=0,
            maximum_parallelism=0,
            maximum_duration_seconds=0,
            required_trust_tier="hardware",
            required_attestations=("executor",),
            human_approval_gates=gates,
            decay_profile="deny",
            rationale_codes=(f"fallback:{reason}",),
            evidence_refs=task.approved_historical_traces,
            fallback_used=True,
            shadow_only=shadow_only,
        )

    def _from_template(
        self,
        task: TaskDescription,
        template: PolicyTemplate,
        *,
        rule_mode: bool,
        shadow_only: bool = False,
    ) -> CandidateTaskPolicyCeiling:
        tools = tuple(tool for tool in template.tools if tool in task.available_tools)
        action_resources = {
            action: tuple(
                resource
                for resource in template.action_resources.get(action, ())
                if resource in task.available_resources
            )
            for action in template.actions
        }
        requested_action = task.user_approved_constraints.get("requested_action")
        requested_resource = task.user_approved_constraints.get("requested_resource")
        if (
            isinstance(requested_action, str)
            and isinstance(requested_resource, str)
            and requested_action in template.actions
            and requested_resource in task.available_resources
        ):
            action_resources[requested_action] = (requested_resource,)
        resources = tuple(sorted({item for values in action_resources.values() for item in values}))
        maximum_write = template.maximum_write_bytes
        gates = set(template.human_approval_gates) | set(task.human_approval_requirements)
        rationale = {"approved-static-template"}
        if rule_mode:
            rationale.add("deterministic-risk-rules")
            if task.data_classification in {"restricted", "secret"}:
                maximum_write = 0
                gates.add("sensitive-data-review")
                rationale.add("sensitive-data-write-removed")
        payload = {
            "task": task.task_fingerprint,
            "template": template.task_type,
            "rule_mode": rule_mode,
            "shadow_only": shadow_only,
            "tools": tools,
            "resources": action_resources,
        }
        return CandidateTaskPolicyCeiling(
            ceiling_id=_candidate_id(payload),
            task_id=task.task_id,
            task_fingerprint=task.task_fingerprint,
            synthesizer_version=self.synthesizer_version,
            model_version="none",
            policy_version=task.global_policy_version,
            confidence_bps=10_000,
            tools=tools,
            actions=template.actions,
            resources=resources,
            action_resources=action_resources,
            argument_constraints=template.argument_constraints,
            network_destinations=template.network_destinations,
            data_classes=template.data_classes,
            maximum_read_bytes=template.maximum_read_bytes,
            maximum_write_bytes=maximum_write,
            maximum_calls=template.maximum_calls,
            maximum_parallelism=template.maximum_parallelism,
            maximum_duration_seconds=template.maximum_duration_seconds,
            required_trust_tier=template.required_trust_tier,
            required_attestations=template.required_attestations,
            human_approval_gates=tuple(sorted(gates)),
            decay_profile=template.decay_profile,
            rationale_codes=tuple(sorted(rationale)),
            evidence_refs=task.approved_historical_traces,
            fallback_used=False,
            shadow_only=shadow_only,
        )

    def _model_proposal(self, task: TaskDescription) -> CandidateTaskPolicyCeiling:
        if self.model is None:
            return self._fallback(task, "model-unavailable")
        outcome: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

        def invoke() -> None:
            try:
                outcome.put((True, self.model.propose(task)), block=False)
            except Exception as exc:
                outcome.put((False, exc), block=False)

        worker = __import__("threading").Thread(target=invoke, daemon=True, name="task-policy-model")
        worker.start()
        worker.join(self.model_timeout_seconds)
        if worker.is_alive():
            return self._fallback(task, "model-timeout")
        try:
            succeeded, value = outcome.get_nowait()
        except queue.Empty:
            return self._fallback(task, "model-no-result")
        if not succeeded:
            return self._fallback(task, "model-error")
        try:
            candidate = CandidateTaskPolicyCeiling.from_dict(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return self._fallback(task, "model-malformed")
        if candidate.model_version != self.model.version:
            return self._fallback(task, "model-version-mismatch")
        if candidate.confidence_bps < self.minimum_confidence_bps:
            return self._fallback(task, "low-confidence")
        return candidate

    def synthesize(self, task: TaskDescription) -> CandidateTaskPolicyCeiling:
        if not isinstance(task, TaskDescription):
            raise PolicySynthesisError("policy synthesizer requires a validated task")
        template = self.templates.get(task.task_type or "")
        if self.mode in {"static", "evaluation"}:
            return self._fallback(task, "unknown-task") if template is None else self._from_template(
                task, template, rule_mode=False
            )
        if self.mode == "rule":
            return self._fallback(task, "unknown-task") if template is None else self._from_template(
                task, template, rule_mode=True
            )
        if self.mode == "model":
            return self._model_proposal(task)
        if self.mode == "shadow":
            proposal = self._model_proposal(task) if self.model is not None else (
                self._fallback(task, "unknown-task", shadow_only=True)
                if template is None
                else self._from_template(task, template, rule_mode=True, shadow_only=True)
            )
            if proposal.shadow_only:
                return proposal
            payload = proposal.to_dict()
            payload["shadow_only"] = True
            return CandidateTaskPolicyCeiling.from_dict(payload)
        raise PolicySynthesisError("unsupported policy synthesis mode")


@dataclass(frozen=True)
class AuthorityReduction:
    source: str
    remove_tools: tuple[str, ...] = ()
    remove_actions: tuple[str, ...] = ()
    remove_resources: tuple[str, ...] = ()
    remove_network_destinations: tuple[str, ...] = ()
    maximum_read_bytes: int | None = None
    maximum_write_bytes: int | None = None
    maximum_calls: int | None = None
    maximum_parallelism: int | None = None
    maximum_duration_seconds: int | None = None
    require_reattestation: bool = False
    require_human_approval: bool = False
    revoke: bool = False

    def __post_init__(self) -> None:
        _text(self.source, "reduction source")
        for name in (
            "remove_tools", "remove_actions", "remove_resources", "remove_network_destinations",
        ):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        for name in (
            "maximum_read_bytes", "maximum_write_bytes", "maximum_calls",
            "maximum_parallelism", "maximum_duration_seconds",
        ):
            value = getattr(self, name)
            if value is not None:
                _nonnegative(value, name)
        for name in ("require_reattestation", "require_human_approval", "revoke"):
            if type(getattr(self, name)) is not bool:
                raise ValidationError("reduction flags must be booleans")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "remove_tools": list(self.remove_tools),
            "remove_actions": list(self.remove_actions),
            "remove_resources": list(self.remove_resources),
            "remove_network_destinations": list(self.remove_network_destinations),
            "maximum_read_bytes": self.maximum_read_bytes,
            "maximum_write_bytes": self.maximum_write_bytes,
            "maximum_calls": self.maximum_calls,
            "maximum_parallelism": self.maximum_parallelism,
            "maximum_duration_seconds": self.maximum_duration_seconds,
            "require_reattestation": self.require_reattestation,
            "require_human_approval": self.require_human_approval,
            "revoke": self.revoke,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorityReduction":
        fields = {
            "source", "remove_tools", "remove_actions", "remove_resources",
            "remove_network_destinations", "maximum_read_bytes", "maximum_write_bytes",
            "maximum_calls", "maximum_parallelism", "maximum_duration_seconds",
            "require_reattestation", "require_human_approval", "revoke",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ValidationError("authority reduction fields are invalid")
        payload = dict(value)
        for name in (
            "remove_tools", "remove_actions", "remove_resources", "remove_network_destinations",
        ):
            payload[name] = tuple(payload[name])
        return cls(**payload)


@dataclass(frozen=True)
class CompiledTaskPolicyCeiling:
    schema: str
    ceiling_id: str
    task_id: str
    task_fingerprint: str
    subject_id: str
    workload_identity: str
    tenant: str
    environment: str
    synthesizer_version: str
    compiler_version: str
    policy_version: str
    candidate_digest: str
    provider_attestation_digest: str
    provider_bundle_digest: str
    provider_key_id: str
    provider_method: str
    provider_trust: str
    required_trust_tier: str
    tools: tuple[str, ...]
    actions: tuple[str, ...]
    action_resources: Mapping[str, tuple[str, ...]]
    argument_constraints: Mapping[str, tuple[str, ...]]
    network_destinations: tuple[str, ...]
    data_classes: tuple[str, ...]
    maximum_read_bytes: int
    maximum_write_bytes: int
    maximum_calls: int
    maximum_parallelism: int
    maximum_duration_seconds: int
    required_attestations: tuple[str, ...]
    human_approval_gates: tuple[str, ...]
    decay_profile: str
    guardian_reductions_digest: str
    issued_at_ms: int
    expires_at_ms: int
    compiled_digest: str

    FIELDS = frozenset({
        "schema", "ceiling_id", "task_id", "task_fingerprint", "subject_id",
        "workload_identity", "tenant", "environment", "synthesizer_version",
        "compiler_version", "policy_version", "candidate_digest",
        "provider_attestation_digest", "provider_bundle_digest", "provider_key_id",
        "provider_method", "provider_trust", "required_trust_tier", "tools", "actions",
        "action_resources", "argument_constraints", "network_destinations", "data_classes",
        "maximum_read_bytes", "maximum_write_bytes", "maximum_calls",
        "maximum_parallelism", "maximum_duration_seconds", "required_attestations",
        "human_approval_gates", "decay_profile", "guardian_reductions_digest",
        "issued_at_ms", "expires_at_ms", "compiled_digest",
    })

    def __post_init__(self) -> None:
        for name in (
            "schema", "ceiling_id", "task_id", "subject_id", "workload_identity", "tenant",
            "environment", "synthesizer_version", "compiler_version", "policy_version",
            "provider_key_id", "provider_method", "decay_profile",
        ):
            _text(getattr(self, name), name)
        for name in (
            "task_fingerprint", "candidate_digest", "provider_attestation_digest",
            "provider_bundle_digest", "guardian_reductions_digest", "compiled_digest",
        ):
            _digest(getattr(self, name), name)
        if self.provider_trust not in TRUST_ORDER or self.required_trust_tier not in TRUST_ORDER:
            raise ValidationError("compiled ceiling trust tier is invalid")
        for name in (
            "tools", "actions", "network_destinations", "data_classes",
            "required_attestations", "human_approval_gates",
        ):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        object.__setattr__(
            self, "action_resources", _mapping_of_string_arrays(self.action_resources, "action resources")
        )
        object.__setattr__(
            self,
            "argument_constraints",
            _mapping_of_string_arrays(self.argument_constraints, "argument constraints"),
        )
        for name in (
            "maximum_read_bytes", "maximum_write_bytes", "maximum_calls",
            "maximum_parallelism", "maximum_duration_seconds", "issued_at_ms", "expires_at_ms",
        ):
            _nonnegative(getattr(self, name), name)
        if self.expires_at_ms <= self.issued_at_ms:
            raise ValidationError("compiled ceiling expiration must follow issuance")
        if set(self.action_resources) != set(self.actions):
            raise ValidationError("compiled ceiling must bind resources for every action")
        if set(self.argument_constraints) != set(self.actions):
            raise ValidationError("compiled ceiling must bind argument constraints for every action")

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "ceiling_id": self.ceiling_id,
            "task_id": self.task_id,
            "task_fingerprint": self.task_fingerprint,
            "subject_id": self.subject_id,
            "workload_identity": self.workload_identity,
            "tenant": self.tenant,
            "environment": self.environment,
            "synthesizer_version": self.synthesizer_version,
            "compiler_version": self.compiler_version,
            "policy_version": self.policy_version,
            "candidate_digest": self.candidate_digest,
            "provider_attestation_digest": self.provider_attestation_digest,
            "provider_bundle_digest": self.provider_bundle_digest,
            "provider_key_id": self.provider_key_id,
            "provider_method": self.provider_method,
            "provider_trust": self.provider_trust,
            "required_trust_tier": self.required_trust_tier,
            "tools": list(self.tools),
            "actions": list(self.actions),
            "action_resources": {key: list(values) for key, values in self.action_resources.items()},
            "argument_constraints": {
                key: list(values) for key, values in self.argument_constraints.items()
            },
            "network_destinations": list(self.network_destinations),
            "data_classes": list(self.data_classes),
            "maximum_read_bytes": self.maximum_read_bytes,
            "maximum_write_bytes": self.maximum_write_bytes,
            "maximum_calls": self.maximum_calls,
            "maximum_parallelism": self.maximum_parallelism,
            "maximum_duration_seconds": self.maximum_duration_seconds,
            "required_attestations": list(self.required_attestations),
            "human_approval_gates": list(self.human_approval_gates),
            "decay_profile": self.decay_profile,
            "guardian_reductions_digest": self.guardian_reductions_digest,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "compiled_digest": self.compiled_digest}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CompiledTaskPolicyCeiling":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ValidationError("compiled ceiling fields are invalid")
        payload = dict(value)
        for name in (
            "tools", "actions", "network_destinations", "data_classes",
            "required_attestations", "human_approval_gates",
        ):
            payload[name] = tuple(payload[name])
        payload["action_resources"] = {
            key: tuple(items) for key, items in payload["action_resources"].items()
        }
        payload["argument_constraints"] = {
            key: tuple(items) for key, items in payload["argument_constraints"].items()
        }
        compiled = cls(**payload)
        compiled.verify_integrity()
        return compiled

    def verify_integrity(self) -> None:
        if self.schema != "event-horizon.compiled-task-ceiling.v1":
            raise PolicyCompilationError("compiled ceiling schema is invalid")
        if digest(self.unsigned_dict()) != self.compiled_digest:
            raise PolicyCompilationError("compiled ceiling digest is invalid")

    def permits(self, request: ActionRequest) -> bool:
        self.verify_integrity()
        return (
            request.agent_id == self.subject_id
            and request.executor_id == self.workload_identity
            and request.operation in self.actions
            and request.resource_id in self.action_resources.get(request.operation, ())
            and set(request.arguments).issubset(self.argument_constraints.get(request.operation, ()))
        )


@dataclass
class TrustedPolicyCompiler:
    global_policy: StaticPolicy
    tool_actions: Mapping[str, frozenset[str]]
    allowed_tenant_environments: Mapping[str, frozenset[str]]
    allowed_network_destinations: frozenset[str] = frozenset()
    allowed_data_classes: frozenset[str] = frozenset({"public", "internal"})
    compiler_version: str = "trusted-policy-compiler-v1"
    global_maximum_read_bytes: int = 1_048_576
    global_maximum_write_bytes: int = 1_048_576
    global_maximum_calls: int = 256
    global_maximum_parallelism: int = 16
    global_maximum_duration_seconds: int = 300
    mandatory_human_approval_gates: frozenset[str] = frozenset()

    def compile(
        self,
        task: TaskDescription,
        candidate: CandidateTaskPolicyCeiling,
        *,
        guardian_reductions: Sequence[AuthorityReduction] = (),
        approved_human_gates: Sequence[str] = (),
        now_ms: int,
    ) -> CompiledTaskPolicyCeiling:
        _nonnegative(now_ms, "compiler time")
        if candidate.shadow_only:
            raise PolicyCompilationError("shadow policy output is not executable authority")
        if candidate.task_id != task.task_id or candidate.task_fingerprint != task.task_fingerprint:
            raise PolicyCompilationError("candidate is not bound to the current task fingerprint")
        if candidate.policy_version != task.global_policy_version:
            raise PolicyCompilationError("candidate policy version is stale or incompatible")
        if task.global_policy_version != self.global_policy.policy_id:
            raise PolicyCompilationError("task policy version does not match the global maximum")
        environments = self.allowed_tenant_environments.get(task.tenant)
        if environments is None or task.environment not in environments:
            raise PolicyCompilationError("tenant or environment is outside global policy")

        global_actions = set(self.global_policy.operations)
        global_resources = {
            resource
            for rule in self.global_policy.operations.values()
            for resource in rule.resources
        }
        known_tools = set(self.tool_actions)
        if set(candidate.tools) - known_tools:
            raise PolicyCompilationError("candidate contains an unknown tool")
        if set(candidate.tools) - set(task.available_tools):
            raise PolicyCompilationError("candidate contains a tool unavailable to the task")
        if set(candidate.actions) - global_actions:
            raise PolicyCompilationError("candidate contains an unknown or globally prohibited action")
        tool_enabled_actions = {
            action for tool in candidate.tools for action in self.tool_actions.get(tool, frozenset())
        }
        if set(candidate.actions) - tool_enabled_actions:
            raise PolicyCompilationError("candidate action is not supplied by its declared tool set")
        if set(candidate.resources) - global_resources:
            raise PolicyCompilationError("candidate contains an unknown or globally prohibited resource")
        if set(candidate.resources) - set(task.available_resources):
            raise PolicyCompilationError("candidate contains a resource unavailable to the task")
        if set(candidate.network_destinations) - set(self.allowed_network_destinations):
            raise PolicyCompilationError("candidate contains an unknown network destination")
        if set(candidate.data_classes) - set(self.allowed_data_classes):
            raise PolicyCompilationError("candidate contains an unknown data class")

        action_resources: dict[str, tuple[str, ...]] = {}
        argument_constraints: dict[str, tuple[str, ...]] = {}
        for action in candidate.actions:
            rule = self.global_policy.operations[action]
            proposed_resources = set(candidate.action_resources.get(action, ()))
            if not proposed_resources.issubset(rule.resources):
                raise PolicyCompilationError("candidate action-resource relationship exceeds global policy")
            proposed_arguments = set(candidate.argument_constraints.get(action, ()))
            if not proposed_arguments.issubset(rule.allowed_argument_keys):
                raise PolicyCompilationError("candidate argument constraints exceed global policy")
            if proposed_arguments & self.global_policy.denied_argument_keys:
                raise PolicyCompilationError("candidate contains globally denied argument keys")
            action_resources[action] = tuple(sorted(proposed_resources))
            argument_constraints[action] = tuple(sorted(proposed_arguments))

        trust = task.provider_attested_trust
        if TRUST_ORDER[trust.effective_trust] < TRUST_ORDER[candidate.required_trust_tier]:
            raise PolicyCompilationError("provider-derived trust is below the candidate requirement")
        if now_ms >= trust.expires_at_ms:
            raise PolicyCompilationError("provider-derived trust has expired")

        required_gates = (
            set(task.human_approval_requirements)
            | set(candidate.human_approval_gates)
            | set(self.mandatory_human_approval_gates)
        )
        approved = set(_strings(tuple(approved_human_gates), "approved human gates"))
        if not required_gates.issubset(approved):
            raise PolicyCompilationError("required human approval gate is unsatisfied")

        tools = set(candidate.tools)
        actions = set(candidate.actions)
        network = set(candidate.network_destinations)
        maximum_read = min(candidate.maximum_read_bytes, self.global_maximum_read_bytes)
        maximum_write = min(candidate.maximum_write_bytes, self.global_maximum_write_bytes)
        maximum_calls = min(candidate.maximum_calls, self.global_maximum_calls)
        maximum_parallelism = min(candidate.maximum_parallelism, self.global_maximum_parallelism)
        maximum_duration = min(
            candidate.maximum_duration_seconds,
            self.global_maximum_duration_seconds,
        )
        reduction_payloads: list[dict[str, Any]] = []
        for reduction in guardian_reductions:
            if not isinstance(reduction, AuthorityReduction):
                raise PolicyCompilationError("guardian reduction is malformed")
            reduction_payloads.append(reduction.to_dict())
            tools -= set(reduction.remove_tools)
            actions -= set(reduction.remove_actions)
            network -= set(reduction.remove_network_destinations)
            for action in list(action_resources):
                action_resources[action] = tuple(
                    item for item in action_resources[action]
                    if item not in set(reduction.remove_resources)
                )
            if reduction.maximum_read_bytes is not None:
                maximum_read = min(maximum_read, reduction.maximum_read_bytes)
            if reduction.maximum_write_bytes is not None:
                maximum_write = min(maximum_write, reduction.maximum_write_bytes)
            if reduction.maximum_calls is not None:
                maximum_calls = min(maximum_calls, reduction.maximum_calls)
            if reduction.maximum_parallelism is not None:
                maximum_parallelism = min(maximum_parallelism, reduction.maximum_parallelism)
            if reduction.maximum_duration_seconds is not None:
                maximum_duration = min(maximum_duration, reduction.maximum_duration_seconds)
            if reduction.require_human_approval and "guardian-review" not in approved:
                raise PolicyCompilationError("guardian-required human approval is unsatisfied")
            if reduction.require_reattestation:
                raise PolicyCompilationError("guardian requires a fresh attestation flow")
            if reduction.revoke:
                raise PolicyCompilationError("guardian revoked the candidate ceiling")

        actions &= {action for tool in tools for action in self.tool_actions[tool]}
        action_resources = {
            action: values for action, values in action_resources.items() if action in actions and values
        }
        actions = set(action_resources)
        argument_constraints = {
            action: argument_constraints[action] for action in sorted(actions)
        }
        expiration = min(
            now_ms + maximum_duration * 1000,
            task.requested_completion_deadline_ms,
            trust.expires_at_ms,
        )
        if expiration <= now_ms or maximum_calls <= 0 or maximum_parallelism <= 0 or not actions:
            raise PolicyCompilationError("compiled authority is empty or already expired")

        unsigned = {
            "schema": "event-horizon.compiled-task-ceiling.v1",
            "ceiling_id": candidate.ceiling_id,
            "task_id": task.task_id,
            "task_fingerprint": task.task_fingerprint,
            "subject_id": task.requesting_subject,
            "workload_identity": task.workload_identity,
            "tenant": task.tenant,
            "environment": task.environment,
            "synthesizer_version": candidate.synthesizer_version,
            "compiler_version": self.compiler_version,
            "policy_version": task.global_policy_version,
            "candidate_digest": digest(candidate.to_dict()),
            "provider_attestation_digest": trust.attestation_digest,
            "provider_bundle_digest": trust.bundle_digest,
            "provider_key_id": trust.key_id,
            "provider_method": trust.method,
            "provider_trust": trust.effective_trust,
            "required_trust_tier": candidate.required_trust_tier,
            "tools": sorted(tools),
            "actions": sorted(actions),
            "action_resources": {
                action: list(action_resources[action]) for action in sorted(action_resources)
            },
            "argument_constraints": {
                action: list(argument_constraints[action]) for action in sorted(argument_constraints)
            },
            "network_destinations": sorted(network),
            "data_classes": sorted(set(candidate.data_classes)),
            "maximum_read_bytes": maximum_read,
            "maximum_write_bytes": maximum_write,
            "maximum_calls": maximum_calls,
            "maximum_parallelism": maximum_parallelism,
            "maximum_duration_seconds": maximum_duration,
            "required_attestations": sorted(set(candidate.required_attestations)),
            "human_approval_gates": sorted(required_gates),
            "decay_profile": candidate.decay_profile,
            "guardian_reductions_digest": digest(reduction_payloads),
            "issued_at_ms": now_ms,
            "expires_at_ms": expiration,
        }
        compiled = CompiledTaskPolicyCeiling(
            schema=unsigned["schema"],
            ceiling_id=unsigned["ceiling_id"],
            task_id=unsigned["task_id"],
            task_fingerprint=unsigned["task_fingerprint"],
            subject_id=unsigned["subject_id"],
            workload_identity=unsigned["workload_identity"],
            tenant=unsigned["tenant"],
            environment=unsigned["environment"],
            synthesizer_version=unsigned["synthesizer_version"],
            compiler_version=unsigned["compiler_version"],
            policy_version=unsigned["policy_version"],
            candidate_digest=unsigned["candidate_digest"],
            provider_attestation_digest=unsigned["provider_attestation_digest"],
            provider_bundle_digest=unsigned["provider_bundle_digest"],
            provider_key_id=unsigned["provider_key_id"],
            provider_method=unsigned["provider_method"],
            provider_trust=unsigned["provider_trust"],
            required_trust_tier=unsigned["required_trust_tier"],
            tools=tuple(unsigned["tools"]),
            actions=tuple(unsigned["actions"]),
            action_resources={key: tuple(value) for key, value in unsigned["action_resources"].items()},
            argument_constraints={
                key: tuple(value) for key, value in unsigned["argument_constraints"].items()
            },
            network_destinations=tuple(unsigned["network_destinations"]),
            data_classes=tuple(unsigned["data_classes"]),
            maximum_read_bytes=unsigned["maximum_read_bytes"],
            maximum_write_bytes=unsigned["maximum_write_bytes"],
            maximum_calls=unsigned["maximum_calls"],
            maximum_parallelism=unsigned["maximum_parallelism"],
            maximum_duration_seconds=unsigned["maximum_duration_seconds"],
            required_attestations=tuple(unsigned["required_attestations"]),
            human_approval_gates=tuple(unsigned["human_approval_gates"]),
            decay_profile=unsigned["decay_profile"],
            guardian_reductions_digest=unsigned["guardian_reductions_digest"],
            issued_at_ms=unsigned["issued_at_ms"],
            expires_at_ms=unsigned["expires_at_ms"],
            compiled_digest=digest(unsigned),
        )
        compiled.verify_integrity()
        return compiled


@dataclass(frozen=True)
class PolicySizingMetrics:
    tools_exposed: int
    tools_invoked: int
    actions_exposed: int
    actions_invoked: int
    dangerous_tools_exposed: int
    unnecessary_privileges_exposed: int
    required_privileges_omitted: int
    task_completed: bool
    task_failure_underprovisioned: bool
    escalation_requests: int
    human_approvals: int
    policy_synthesis_latency_ms: int
    policy_compiler_latency_ms: int
    attack_succeeded: bool
    false_denial: bool
    risk_weighted_authority_exposure: int
    skill_economy_ratio_millis: int
    composite_score_millis: int

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


def evaluate_policy_sizing(
    *,
    exposed_tools: Sequence[str],
    invoked_tools: Sequence[str],
    exposed_actions: Sequence[str],
    invoked_actions: Sequence[str],
    required_tools: Sequence[str],
    dangerous_tools: Sequence[str],
    task_completed: bool,
    task_failure_underprovisioned: bool,
    escalation_requests: int,
    human_approvals: int,
    synthesis_latency_ms: int,
    compiler_latency_ms: int,
    attack_succeeded: bool,
    false_denial: bool,
    risk_weights: Mapping[str, int] | None = None,
) -> PolicySizingMetrics:
    exposed = set(exposed_tools)
    invoked = set(invoked_tools)
    actions = set(exposed_actions)
    invoked_action_set = set(invoked_actions)
    required = set(required_tools)
    dangerous = set(dangerous_tools)
    unnecessary = exposed - (invoked | required)
    omitted = required - exposed
    ratio = 1000 if not exposed and not required else (
        0 if not exposed else min(1000, len(invoked | required) * 1000 // len(exposed))
    )
    weights = dict(risk_weights or {})
    risk_exposure = sum(max(0, weights.get(tool, 1)) for tool in exposed)
    completion_score = 1000 if task_completed else 0
    least_authority_score = max(0, 1000 - len(unnecessary) * 125 - risk_exposure * 10)
    denial_penalty = 300 if false_denial or task_failure_underprovisioned else 0
    attack_penalty = 1000 if attack_succeeded else 0
    escalation_penalty = min(300, escalation_requests * 50)
    composite = max(
        0,
        (completion_score * 5 + least_authority_score * 3 + ratio * 2) // 10
        - denial_penalty
        - attack_penalty
        - escalation_penalty,
    )
    return PolicySizingMetrics(
        tools_exposed=len(exposed),
        tools_invoked=len(invoked),
        actions_exposed=len(actions),
        actions_invoked=len(invoked_action_set),
        dangerous_tools_exposed=len(exposed & dangerous),
        unnecessary_privileges_exposed=len(unnecessary),
        required_privileges_omitted=len(omitted),
        task_completed=task_completed,
        task_failure_underprovisioned=task_failure_underprovisioned,
        escalation_requests=_nonnegative(escalation_requests, "escalation requests"),
        human_approvals=_nonnegative(human_approvals, "human approvals"),
        policy_synthesis_latency_ms=_nonnegative(synthesis_latency_ms, "synthesis latency"),
        policy_compiler_latency_ms=_nonnegative(compiler_latency_ms, "compiler latency"),
        attack_succeeded=bool(attack_succeeded),
        false_denial=bool(false_denial),
        risk_weighted_authority_exposure=risk_exposure,
        skill_economy_ratio_millis=ratio,
        composite_score_millis=composite,
    )


@dataclass(frozen=True)
class PolicyPlan:
    proposed: CandidateTaskPolicyCeiling
    enforcement_candidate: CandidateTaskPolicyCeiling
    shadow: bool


@dataclass
class AdaptivePolicyController:
    proposal_synthesizer: TaskPolicySynthesizer
    enforcement_synthesizer: TaskPolicySynthesizer

    def plan(self, task: TaskDescription) -> PolicyPlan:
        proposed = self.proposal_synthesizer.synthesize(task)
        if self.proposal_synthesizer.mode == "shadow":
            enforced = self.enforcement_synthesizer.synthesize(task)
            if enforced.shadow_only:
                raise PolicySynthesisError("shadow enforcement synthesizer produced shadow output")
            return PolicyPlan(proposed, enforced, True)
        return PolicyPlan(proposed, proposed, False)


def default_policy_templates() -> dict[str, PolicyTemplate]:
    return {
        "summarization": PolicyTemplate(
            task_type="summarization",
            tools=("object-reader",),
            actions=("object.read",),
            action_resources={"object.read": ("target-source", "public-evidence")},
            argument_constraints={"object.read": ("length", "offset")},
            data_classes=("public", "internal"),
            maximum_read_bytes=65_536,
            maximum_write_bytes=0,
            maximum_calls=4,
            maximum_parallelism=1,
            maximum_duration_seconds=60,
        ),
        "read-only-analysis": PolicyTemplate(
            task_type="read-only-analysis",
            tools=("object-reader", "safe-compute"),
            actions=("compute.run", "object.read"),
            action_resources={
                "object.read": ("target-source", "public-evidence"),
                "compute.run": ("safe-hash",),
            },
            argument_constraints={
                "object.read": ("length", "offset"),
                "compute.run": ("value",),
            },
            data_classes=("public", "internal"),
            maximum_read_bytes=65_536,
            maximum_write_bytes=0,
            maximum_calls=8,
            maximum_parallelism=2,
            maximum_duration_seconds=120,
        ),
        "deployment": PolicyTemplate(
            task_type="deployment",
            tools=("deployment",),
            actions=("deployment.apply",),
            action_resources={"deployment.apply": ("approved-staging",)},
            argument_constraints={"deployment.apply": ("artifact_digest", "replicas")},
            data_classes=("internal",),
            maximum_read_bytes=16_384,
            maximum_write_bytes=65_536,
            maximum_calls=2,
            maximum_parallelism=1,
            maximum_duration_seconds=120,
            required_trust_tier="hardware",
            human_approval_gates=("deployment-approval",),
            decay_profile="single-effect",
        ),
    }
