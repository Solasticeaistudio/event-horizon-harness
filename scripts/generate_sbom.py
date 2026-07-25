#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM for Node and pinned Python dependencies."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
import uuid
from pathlib import Path
from typing import Any


PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)$")
PYTHON_DEPENDENCY_EDGES = {
    "cryptography": ["cffi"],
    "cffi": ["pycparser"],
    "pycparser": [],
}


def pinned(requirement: str) -> tuple[str, str]:
    match = PIN.fullmatch(requirement)
    if match is None:
        raise ValueError(f"SBOM generation requires an exact dependency pin: {requirement}")
    return match.group(1).lower(), match.group(2)


def component(name: str, version: str, group: str) -> dict[str, Any]:
    reference = f"pkg:pypi/{name}@{version}"
    return {
        "bom-ref": reference,
        "type": "library",
        "name": name,
        "version": version,
        "scope": "required" if group == "runtime" else "optional",
        "purl": reference,
        "properties": [
            {"name": "event-horizon:python-dependency-group", "value": group},
        ],
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    npm = shutil.which("npm") or shutil.which("npm.cmd")
    if npm is None:
        raise RuntimeError("npm is required to generate the combined SBOM")
    npm_result = subprocess.run(
        [
            npm,
            "sbom",
            "--package-lock-only",
            "--sbom-format",
            "cyclonedx",
            "--sbom-type",
            "application",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    document = json.loads(npm_result.stdout)
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    runtime = dict(pinned(value) for value in project["project"]["dependencies"])
    build = dict(pinned(value) for value in project["build-system"]["requires"])

    document["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, project['project']['name'] + '@' + project['project']['version'])}"
    document["metadata"]["timestamp"] = "2026-07-24T00:00:00.000Z"
    document["metadata"]["component"]["name"] = project["project"]["name"]
    document["metadata"]["tools"].append(
        {"vendor": "Event Horizon", "name": "pinned-pyproject dependency export", "version": "0.4.0"}
    )
    for name, version in sorted(runtime.items()):
        document["components"].append(component(name, version, "runtime"))
    for name, version in sorted(build.items()):
        document["components"].append(component(name, version, "build"))

    root_reference = document["metadata"]["component"]["bom-ref"]
    root_dependency = next(item for item in document["dependencies"] if item["ref"] == root_reference)
    root_dependency["dependsOn"].extend(
        f"pkg:pypi/{name}@{version}" for name, version in sorted(runtime.items())
    )
    for name, version in sorted(runtime.items()):
        children = [
            f"pkg:pypi/{child}@{runtime[child]}"
            for child in PYTHON_DEPENDENCY_EDGES.get(name, [])
        ]
        document["dependencies"].append(
            {"ref": f"pkg:pypi/{name}@{version}", "dependsOn": children}
        )
    for name, version in sorted(build.items()):
        document["dependencies"].append(
            {"ref": f"pkg:pypi/{name}@{version}", "dependsOn": []}
        )

    output = root / "artifacts" / "sbom.cdx.json"
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"CycloneDX SBOM: {len(document['components'])} components -> {output.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
