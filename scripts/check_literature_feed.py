#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path

from event_horizon.canonical import digest
from event_horizon.literature_feed import SandboxEscapeBenchAdapter


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "literature-fixtures" / "sandbox-escape-bench.json"


def live_metadata(adapter: SandboxEscapeBenchAdapter, technique_ids: list[str]) -> dict:
    request = urllib.request.Request(
        "https://api.github.com/repos/UKGovernmentBEIS/sandbox_escape_bench/commits/main",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "event-horizon-literature-check"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(65_537)
    if len(raw) > 65_536:
        raise ValueError("literature metadata response exceeds its byte bound")
    commit = json.loads(raw)
    version = commit["sha"]
    return {
        "source_version": version,
        "source_digest": digest({"source": adapter.source, "source_version": version, "license": "MIT"}),
        "license": "MIT",
        "technique_ids": technique_ids,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Report reviewed literature-feed drift")
    parser.add_argument("--live", action="store_true", help="retrieve metadata only; never code")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    adapter = SandboxEscapeBenchAdapter()
    fixture = adapter.load(FIXTURE)
    ids = [item.technique_id for item in fixture.techniques]
    first = fixture.techniques[0]
    observed = live_metadata(adapter, ids) if args.live else {
        "source_version": first.source_version,
        "source_digest": first.source_digest,
        "license": first.license,
        "technique_ids": ids,
    }
    report = adapter.drift_report(fixture, observed).to_dict()
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
