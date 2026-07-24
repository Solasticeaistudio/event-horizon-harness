from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .broker import CapabilityBroker, CapabilityVerifier
from .canonical import digest
from .models import ActionRequest, ExecutionResult, IssuedCapability
from .recorder import ExternalRecorder


@dataclass
class SacrificialExecutor:
    executor_id: str
    device_id: str
    measurement: str
    verifier_policy_digest: str
    policy_digest: str
    broker: CapabilityBroker | CapabilityVerifier
    recorder: ExternalRecorder
    objects: dict[str, Any] = field(default_factory=dict)
    compute_profiles: dict[str, Callable[[dict[str, Any]], Any]] = field(default_factory=dict)

    def execute(
        self,
        request: ActionRequest,
        capability: IssuedCapability,
        attestation: Mapping[str, Any] | None = None,
    ) -> ExecutionResult:
        try:
            attestation_digest = None
            bundle_digest = None
            if attestation is not None:
                attestation_copy = dict(attestation)
                attestation_digest = str(attestation_copy.pop("resultDigest", ""))
                if not attestation_digest or digest(attestation_copy) != attestation_digest:
                    raise PermissionError("attestation result digest mismatch")
                bundle_digest = str(attestation_copy.get("bundleDigest", ""))
                measurements = attestation_copy.get("measurements", {})
                if not isinstance(measurements, Mapping) or measurements.get("executor") != self.measurement:
                    raise PermissionError("attested executor measurement mismatch")
            claims = self.broker.verify_and_consume(
                capability,
                request,
                executor_measurement=self.measurement,
                device_id=self.device_id,
                attestation_digest=attestation_digest,
                attestation_bundle_digest=bundle_digest,
                verifier_policy_digest=self.verifier_policy_digest,
                policy_digest=self.policy_digest,
            )
            if request.operation == "object.read":
                if request.resource_id not in self.objects:
                    raise KeyError("object not found")
                output = self.objects[request.resource_id]
            elif request.operation == "compute.run":
                fn = self.compute_profiles.get(request.resource_id)
                if fn is None:
                    raise KeyError("compute profile not found")
                output = fn(dict(request.arguments))
            else:
                raise PermissionError("executor has no implementation for operation")
            encoded = json.dumps(output, sort_keys=True, default=str).encode("utf-8")
            if len(encoded) > claims.max_output_bytes:
                raise PermissionError("result exceeds capability output envelope")
            result = ExecutionResult(True, request.operation, request.resource_id, output, len(encoded))
            self.recorder.append("execution.completed", {
                "request_id": request.request_id,
                "capability_id": claims.capability_id,
                "success": True,
                "output_bytes": len(encoded),
            })
            return result
        except Exception as exc:
            self.recorder.append("execution.denied", {
                "request_id": request.request_id,
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
            return ExecutionResult(False, request.operation, request.resource_id, error=str(exc))
