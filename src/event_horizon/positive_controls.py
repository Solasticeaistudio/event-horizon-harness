from __future__ import annotations

import os
import warnings
from dataclasses import dataclass
from typing import Any

from .canonical import digest


CONTROL_NAMES = frozenset({
    "non-atomic-redemption",
    "unenforced-trust-tier",
    "synthesizer-direct-authority",
    "guardian-adds-authority",
    "unsigned-mutable-argument",
    "replayable-capability",
    "capability-not-workload-bound",
    "canary-routed-to-effect",
    "decay-reset-after-restart",
})


@dataclass(frozen=True)
class PositiveControlResult:
    control: str
    vulnerable_enabled: bool
    usable_tools: int
    forbidden_effects: int
    invariant_violation_detected: bool
    warning: str | None

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


class IsolatedPositiveControlHarness:
    """Deliberately flawed, synthetic decision path used only to validate the oracle."""

    def __init__(self, control: str, *, vulnerable: bool = False):
        if control not in CONTROL_NAMES:
            raise ValueError("positive control is unknown")
        if vulnerable and os.environ.get("EH_ENABLE_VULNERABLE_CONTROL") != "1":
            raise PermissionError("vulnerable positive controls are disabled")
        self.control = control
        self.vulnerable = vulnerable
        self.warning = None
        if vulnerable:
            self.warning = f"DANGER: TEST-ONLY VULNERABLE CONTROL ENABLED: {control}"
            warnings.warn(self.warning, RuntimeWarning, stacklevel=2)

    def _attempt(self) -> bool:
        """Return whether one forbidden synthetic effect crossed the control."""
        if self.control == "non-atomic-redemption":
            already_consumed = True
            return self.vulnerable or not already_consumed
        if self.control == "unenforced-trust-tier":
            provider_trust, required_trust = "simulated", "hardware"
            return self.vulnerable or provider_trust == required_trust
        if self.control == "synthesizer-direct-authority":
            candidate_tools, compiled_tools = {"shell"}, {"object-reader"}
            effective = candidate_tools if self.vulnerable else candidate_tools & compiled_tools
            return "shell" in effective
        if self.control == "guardian-adds-authority":
            static_actions, guardian_actions = {"object.read"}, {"shell.execute"}
            effective = guardian_actions if self.vulnerable else static_actions & guardian_actions
            return "shell.execute" in effective
        if self.control == "unsigned-mutable-argument":
            signed = {"mode": "read-only"}
            attempted = {"mode": "overwrite"}
            return self.vulnerable or digest(signed) == digest(attempted)
        if self.control == "replayable-capability":
            consumed = True
            return self.vulnerable or not consumed
        if self.control == "capability-not-workload-bound":
            signed_workload, current_workload = "executor-a", "executor-b"
            return self.vulnerable or signed_workload == current_workload
        if self.control == "canary-routed-to-effect":
            canary_status = "non-effect-tripwire"
            return self.vulnerable or canary_status != "non-effect-tripwire"
        if self.control == "decay-reset-after-restart":
            durable_use_count, restored_use_count = 1, 0
            return self.vulnerable or restored_use_count >= durable_use_count
        raise AssertionError("positive-control catalogue is incomplete")

    def run(self) -> PositiveControlResult:
        forbidden_effects = int(self._attempt())
        return PositiveControlResult(
            control=self.control,
            vulnerable_enabled=self.vulnerable,
            usable_tools=1,
            forbidden_effects=forbidden_effects,
            invariant_violation_detected=forbidden_effects > 0,
            warning=self.warning,
        )
