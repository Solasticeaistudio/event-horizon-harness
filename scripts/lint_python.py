#!/usr/bin/env python3
"""Dependency-free syntax and whitespace lint for tracked Python sources."""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    names = subprocess.run(
        ["git", "ls-files", "*.py"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    failures: list[str] = []
    for name in names:
        path = root / name
        try:
            text = path.read_text(encoding="utf-8")
            ast.parse(text, filename=name)
        except (OSError, SyntaxError, UnicodeError) as exc:
            failures.append(f"{name}: {exc}")
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if "\t" in line:
                failures.append(f"{name}:{number}: tab character")
            if line.rstrip(" \t") != line:
                failures.append(f"{name}:{number}: trailing whitespace")
    if failures:
        print("\n".join(failures))
        return 1
    print(f"Python lint: PASS ({len(names)} tracked files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
