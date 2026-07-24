#!/usr/bin/env python3
"""Fail when prohibited generated artifacts, secrets, or stale names are tracked."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path, PurePosixPath


FORBIDDEN_PARTS = {
    "node_modules", "__pycache__", ".pytest_cache", "coverage", ".nyc_output",
    "dist", "build",
}
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".zip", ".key", ".p12", ".pfx"}
PRIVATE_KEY_PATTERN = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
LEGACY_PATTERN = re.compile(b"hard" + b"proof", re.IGNORECASE)
LEGACY_ALLOWED = {"CHANGELOG.md", "docs/RENAMING_NOTES.md"}
MAX_TRACKED_BYTES = 5 * 1024 * 1024


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    output = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    names = [value.decode("utf-8") for value in output.split(b"\0") if value]
    failures: list[str] = []
    for name in names:
        normalized = PurePosixPath(name)
        lower_parts = {part.lower() for part in normalized.parts}
        lower_name = normalized.name.lower()
        if lower_parts & FORBIDDEN_PARTS or any(part.endswith(".egg-info") for part in lower_parts):
            failures.append(f"generated directory is tracked: {name}")
        if normalized.suffix.lower() in FORBIDDEN_SUFFIXES:
            failures.append(f"prohibited artifact is tracked: {name}")
        if lower_name == ".env" or (lower_name.startswith(".env.") and lower_name != ".env.example"):
            failures.append(f"environment secret file is tracked: {name}")
        path = root / name
        if not path.is_file():
            continue
        size = path.stat().st_size
        if size > MAX_TRACKED_BYTES:
            failures.append(f"tracked file exceeds 5 MiB: {name}")
            continue
        content = path.read_bytes()
        if PRIVATE_KEY_PATTERN.search(content):
            failures.append(f"private key material is tracked: {name}")
        if name not in LEGACY_ALLOWED and LEGACY_PATTERN.search(content):
            failures.append(f"legacy attestation name remains active: {name}")
    if failures:
        print("\n".join(failures))
        return 1
    print(f"repository policy: PASS ({len(names)} tracked paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
