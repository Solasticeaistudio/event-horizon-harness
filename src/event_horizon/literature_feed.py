from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .canonical import digest, strict_json_loads


SOURCE_CATEGORIES = frozenset({
    "sandbox-escape", "agent-tool-security", "capability-least-privilege",
    "prompt-injection", "mcp-tool-protocol", "runtime-orchestration-kernel",
})
REVIEW_STATES = frozenset({"pending-human-review", "approved", "rejected"})


class LiteratureFeedError(ValueError):
    pass


@dataclass(frozen=True)
class TechniqueDefinition:
    source: str
    source_version: str
    publication_date: str
    retrieval_date: str
    license: str
    source_digest: str
    technique_id: str
    technique_category: str
    affected_boundary: str
    prerequisites: tuple[str, ...]
    expected_indicators: tuple[str, ...]
    safe_simulation_method: str
    success_condition: str
    mapped_event_horizon_invariant: str
    review_status: str
    reviewer: str
    campaign_template_version: str

    FIELDS = frozenset({
        "source", "source_version", "publication_date", "retrieval_date", "license",
        "source_digest", "technique_id", "technique_category", "affected_boundary",
        "prerequisites", "expected_indicators", "safe_simulation_method",
        "success_condition", "mapped_event_horizon_invariant", "review_status",
        "reviewer", "campaign_template_version",
    })

    def __post_init__(self) -> None:
        for name in (
            "source", "source_version", "publication_date", "retrieval_date", "license",
            "technique_id", "affected_boundary", "safe_simulation_method",
            "success_condition", "mapped_event_horizon_invariant", "reviewer",
            "campaign_template_version",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 1_024:
                raise LiteratureFeedError(f"technique {name} is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.source_digest):
            raise LiteratureFeedError("technique source digest is invalid")
        if self.technique_category not in SOURCE_CATEGORIES:
            raise LiteratureFeedError("technique category is unsupported")
        if self.review_status not in REVIEW_STATES:
            raise LiteratureFeedError("technique review state is invalid")
        if not re.fullmatch(r"EH-(?:[1-9]|1[01])", self.mapped_event_horizon_invariant):
            raise LiteratureFeedError("technique invariant mapping is invalid")
        for name in ("prerequisites", "expected_indicators"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or not values or len(values) > 32:
                raise LiteratureFeedError(f"technique {name} is invalid")
            if any(not isinstance(item, str) or not item for item in values):
                raise LiteratureFeedError(f"technique {name} items are invalid")
        forbidden = ("exploit code", "download and execute", "public target", "credential dump")
        if any(item in self.safe_simulation_method.lower() for item in forbidden):
            raise LiteratureFeedError("unsafe campaign material is prohibited")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TechniqueDefinition":
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise LiteratureFeedError("technique fields are invalid")
        payload = dict(value)
        payload["prerequisites"] = tuple(payload["prerequisites"])
        payload["expected_indicators"] = tuple(payload["expected_indicators"])
        return cls(**payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            name: list(value) if isinstance(value, tuple) else value
            for name, value in self.__dict__.items()
        }


@dataclass(frozen=True)
class LiteratureFixture:
    schema: str
    adapter: str
    techniques: tuple[TechniqueDefinition, ...]

    @classmethod
    def load(cls, path: str | Path) -> "LiteratureFixture":
        try:
            value = strict_json_loads(Path(path).read_bytes())
        except (OSError, ValueError) as exc:
            raise LiteratureFeedError("literature fixture is unavailable or malformed") from exc
        if not isinstance(value, Mapping) or set(value) != {"schema", "adapter", "techniques"}:
            raise LiteratureFeedError("literature fixture fields are invalid")
        if value["schema"] != "event-horizon.literature-techniques.v1":
            raise LiteratureFeedError("literature fixture schema is unsupported")
        techniques = tuple(TechniqueDefinition.from_dict(item) for item in value["techniques"])
        ids = [item.technique_id for item in techniques]
        if not techniques or len(ids) != len(set(ids)):
            raise LiteratureFeedError("literature technique IDs are empty or duplicated")
        return cls(value["schema"], value["adapter"], techniques)

    @property
    def fixture_digest(self) -> str:
        return digest({
            "schema": self.schema,
            "adapter": self.adapter,
            "techniques": [item.to_dict() for item in self.techniques],
        })


@dataclass(frozen=True)
class LiteratureDriftReport:
    adapter: str
    pinned_source_version: str
    observed_source_version: str
    new_techniques: tuple[str, ...]
    changed_techniques: tuple[str, ...]
    removed_techniques: tuple[str, ...]
    source_hash_changed: bool
    adapter_failures: tuple[str, ...]
    license_changes: tuple[str, ...]
    campaigns_requiring_review: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            name: list(value) if isinstance(value, tuple) else value
            for name, value in self.__dict__.items()
        }


class SandboxEscapeBenchAdapter:
    name = "sandbox-escape-bench-metadata-v1"
    source = "https://github.com/UKGovernmentBEIS/sandbox_escape_bench"

    def load(self, path: str | Path) -> LiteratureFixture:
        fixture = LiteratureFixture.load(path)
        if fixture.adapter != self.name:
            raise LiteratureFeedError("fixture does not belong to the SandboxEscapeBench adapter")
        if any(item.source != self.source for item in fixture.techniques):
            raise LiteratureFeedError("fixture contains a substituted source")
        return fixture

    def drift_report(
        self,
        fixture: LiteratureFixture,
        observed: Mapping[str, Any],
    ) -> LiteratureDriftReport:
        required = {"source_version", "source_digest", "license", "technique_ids"}
        if not isinstance(observed, Mapping) or set(observed) != required:
            raise LiteratureFeedError("observed literature metadata is malformed")
        pinned = {item.technique_id: digest(item.to_dict()) for item in fixture.techniques}
        observed_ids = observed["technique_ids"]
        if not isinstance(observed_ids, Sequence) or isinstance(observed_ids, str):
            raise LiteratureFeedError("observed technique IDs are malformed")
        observed_set = set(observed_ids)
        pinned_set = set(pinned)
        source_versions = {item.source_version for item in fixture.techniques}
        source_digests = {item.source_digest for item in fixture.techniques}
        licenses = {item.license for item in fixture.techniques}
        if len(source_versions) != 1 or len(source_digests) != 1 or len(licenses) != 1:
            raise LiteratureFeedError("pinned source metadata is inconsistent")
        changed = tuple(sorted(pinned_set & observed_set)) if (
            observed["source_version"] not in source_versions
            or observed["source_digest"] not in source_digests
        ) else ()
        requiring_review = tuple(sorted(
            item.technique_id for item in fixture.techniques if item.review_status != "approved"
        ))
        return LiteratureDriftReport(
            adapter=self.name,
            pinned_source_version=next(iter(source_versions)),
            observed_source_version=str(observed["source_version"]),
            new_techniques=tuple(sorted(observed_set - pinned_set)),
            changed_techniques=changed,
            removed_techniques=tuple(sorted(pinned_set - observed_set)),
            source_hash_changed=observed["source_digest"] not in source_digests,
            adapter_failures=(),
            license_changes=() if observed["license"] in licenses else (str(observed["license"]),),
            campaigns_requiring_review=requiring_review,
        )
