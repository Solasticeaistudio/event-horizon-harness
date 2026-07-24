from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

from .attestation import DevelopmentAttestationProvider
from .broker import CapabilityBroker
from .canonical import digest
from .executor import SacrificialExecutor
from .guardians import AttestationGuardian, GuardianQuorum, LineageBudgetGuardian, PolicyGuardian, SequenceGuardian
from .intent_canonicalizer import IntentCanonicalizer
from .policy import OperationRule, StaticPolicy
from .recorder import ExternalRecorder


def build_local_harness(workdir: str | Path, *, ttl_seconds: float = 10.0):
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    recorder = ExternalRecorder(workdir / "external-recorder" / "events.jsonl")
    attestation_seed = "event-horizon-attestation-rebuild"
    measurement = hashlib.sha256(f"simulator:executor:{attestation_seed}".encode()).hexdigest()
    attestation_root = Path(__file__).resolve().parents[2] / "attestation"
    attestation_provider = DevelopmentAttestationProvider(
        attestation_root=attestation_root,
        device_seeds={"exec-1": attestation_seed},
    )
    policy = StaticPolicy(
        policy_id="eh-demo-policy-v0.3",
        allowed_agents=frozenset({"attacker-agent"}),
        allowed_executors=frozenset({"exec-1"}),
        operations={
            "object.read": OperationRule(
                resources=frozenset({"target-source", "public-evidence"}),
                allowed_argument_keys=frozenset({"offset", "length"}),
                max_output_bytes=65536,
            ),
            "compute.run": OperationRule(
                resources=frozenset({"safe-hash"}),
                allowed_argument_keys=frozenset({"value"}),
                max_output_bytes=4096,
            ),
        },
    )
    guardians = [
        PolicyGuardian(policy),
        AttestationGuardian(attestation_provider),
        LineageBudgetGuardian(max_requests_per_session=12, max_denials_per_session=5),
        SequenceGuardian(),
    ]
    quorum = GuardianQuorum(guardians)
    broker = CapabilityBroker(secrets.token_bytes(32), ttl_seconds=ttl_seconds)
    neural = IntentCanonicalizer(policy, quorum, broker, recorder, {"exec-1": measurement})
    verifier_policy_digest = digest({
        "provider": "attestation-development-bridge",
        "deviceId": "exec-1",
        "minimumTrust": "simulated",
        "expectedExecutorMeasurement": measurement,
    })
    executor = SacrificialExecutor(
        executor_id="exec-1",
        device_id="exec-1",
        measurement=measurement,
        verifier_policy_digest=verifier_policy_digest,
        policy_digest=policy.policy_digest,
        broker=broker,
        recorder=recorder,
        objects={
            "target-source": {"name": "synthetic-target", "content": "safe fixture"},
            "public-evidence": {"finding": "contained"},
        },
        compute_profiles={"safe-hash": lambda args: {"sha256": __import__('hashlib').sha256(str(args.get('value', '')).encode()).hexdigest()}},
    )
    return neural, executor, recorder, broker
